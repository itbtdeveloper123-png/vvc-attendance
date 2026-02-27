<?php
// Output buffering for AJAX flexibility
ob_start();

require_once __DIR__ . '/config.php';
require_once __DIR__ . '/vendor/autoload.php';
// We'll use fully qualified names for WebPush to avoid conflicts with existing code

// Helper: Ensure core tables exist
function ensure_core_tables($mysqli) {
    // 1. users table
    $mysqli->query("CREATE TABLE IF NOT EXISTS users (
        employee_id VARCHAR(64) PRIMARY KEY,
        password VARCHAR(255) NOT NULL,
        name VARCHAR(191) NOT NULL,
        user_role ENUM('Admin', 'User') NOT NULL DEFAULT 'User',
        access_mode ENUM('Free', 'Paid', 'Expired') NOT NULL DEFAULT 'Free',
        expiry_datetime DATETIME DEFAULT NULL,
        is_super_admin BOOLEAN NOT NULL DEFAULT 0,
        created_by_admin_id VARCHAR(64) DEFAULT NULL,
        custom_data LONGTEXT DEFAULT NULL,
        employment_status ENUM('Active', 'Suspended', 'Resigned') NOT NULL DEFAULT 'Active',
        leave_date DATE DEFAULT NULL,
        telegram_chat_id VARCHAR(64) DEFAULT NULL,
        expiry_notification_sent BOOLEAN NOT NULL DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_role (user_role),
        KEY idx_created_by (created_by_admin_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 2. checkin_logs
    $mysqli->query("CREATE TABLE IF NOT EXISTS checkin_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        log_datetime DATETIME NOT NULL,
        late_reason TEXT DEFAULT NULL,
        noted TEXT DEFAULT NULL,
        KEY idx_emp_date (employee_id, log_datetime)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 3. requests_logs
    $mysqli->query("CREATE TABLE IF NOT EXISTS requests_logs (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        request_type VARCHAR(100) DEFAULT NULL,
        request_status ENUM('Pending', 'Approved', 'Rejected') DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_emp_created (employee_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 4. attendance_rules
    $mysqli->query("CREATE TABLE IF NOT EXISTS attendance_rules (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        type VARCHAR(50) DEFAULT NULL,
        start_time TIME DEFAULT NULL,
        end_time TIME DEFAULT NULL,
        status VARCHAR(50) DEFAULT NULL,
        created_by_admin_id VARCHAR(64) DEFAULT NULL,
        KEY idx_emp (employee_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 5. user_locations
    $mysqli->query("CREATE TABLE IF NOT EXISTS user_locations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        location_id INT NOT NULL,
        custom_radius_meters INT DEFAULT NULL,
        created_by_admin_id VARCHAR(64) DEFAULT NULL,
        KEY idx_emp_loc (employee_id, location_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 6. active_tokens
    $mysqli->query("CREATE TABLE IF NOT EXISTS active_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        token VARCHAR(255) NOT NULL UNIQUE,
        expires_at DATETIME NOT NULL,
        KEY idx_token (token)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 7. sidebar_settings
    $mysqli->query("CREATE TABLE IF NOT EXISTS sidebar_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        menu_key VARCHAR(100) NOT NULL,
        menu_text VARCHAR(191) NOT NULL,
        icon_class VARCHAR(100) NOT NULL,
        menu_order INT NOT NULL DEFAULT 0,
        UNIQUE KEY uniq_admin_menu (admin_id, menu_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 8. app_settings
    $mysqli->query("CREATE TABLE IF NOT EXISTS app_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        setting_key VARCHAR(100) NOT NULL,
        setting_value LONGTEXT DEFAULT NULL,
        UNIQUE KEY uniq_admin_setting (admin_id, setting_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 9. app_scan_settings
    $mysqli->query("CREATE TABLE IF NOT EXISTS app_scan_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        setting_key VARCHAR(100) NOT NULL,
        setting_value LONGTEXT DEFAULT NULL,
        UNIQUE KEY uniq_admin_scan (admin_id, setting_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 10. user_form_fields
    $mysqli->query("CREATE TABLE IF NOT EXISTS user_form_fields (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        field_key VARCHAR(100) NOT NULL,
        field_label VARCHAR(191) NOT NULL,
        field_type VARCHAR(50) NOT NULL DEFAULT 'text',
        is_required TINYINT(1) NOT NULL DEFAULT 0,
        field_order INT NOT NULL DEFAULT 0,
        is_deletable TINYINT(1) NOT NULL DEFAULT 1,
        UNIQUE KEY uniq_admin_field (admin_id, field_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 11. request_form_fields
    $mysqli->query("CREATE TABLE IF NOT EXISTS request_form_fields (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        field_key VARCHAR(100) NOT NULL,
        field_label VARCHAR(191) NOT NULL,
        field_type VARCHAR(50) NOT NULL DEFAULT 'text',
        is_required TINYINT(1) NOT NULL DEFAULT 0,
        field_order INT NOT NULL DEFAULT 0,
        is_deletable TINYINT(1) NOT NULL DEFAULT 1,
        UNIQUE KEY uniq_admin_req_field (admin_id, field_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 12. page_access_settings
    $mysqli->query("CREATE TABLE IF NOT EXISTS page_access_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        page_key VARCHAR(100) NOT NULL,
        action_key VARCHAR(100) NOT NULL,
        UNIQUE KEY uniq_emp_page_action (employee_id, page_key, action_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 13. signature_history
    $mysqli->query("CREATE TABLE IF NOT EXISTS signature_history (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        signature_base64 LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_emp_created (employee_id, created_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 14. notifications & user_notifications
    $mysqli->query("CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        title VARCHAR(191) NOT NULL,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $mysqli->query("CREATE TABLE IF NOT EXISTS user_notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        notification_id INT NOT NULL,
        employee_id VARCHAR(64) NOT NULL,
        is_read TINYINT(1) NOT NULL DEFAULT 0,
        read_at DATETIME DEFAULT NULL,
        KEY idx_emp_read (employee_id, is_read)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 15. submenu_settings
    $mysqli->query("CREATE TABLE IF NOT EXISTS submenu_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        menu_key VARCHAR(100) NOT NULL,
        action_key VARCHAR(100) NOT NULL,
        submenu_text VARCHAR(191) NOT NULL,
        UNIQUE KEY uniq_admin_submenu (admin_id, menu_key, action_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 16. locations
    $mysqli->query("CREATE TABLE IF NOT EXISTS locations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        location_name VARCHAR(191) NOT NULL,
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        radius_meters INT DEFAULT 100,
        qr_secret VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_by_admin_id VARCHAR(64) DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 17. auth_tokens
    $mysqli->query("CREATE TABLE IF NOT EXISTS auth_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        selector VARCHAR(64) NOT NULL UNIQUE,
        hashed_validator VARCHAR(255) NOT NULL,
        user_id VARCHAR(64) NOT NULL,
        expires DATETIME NOT NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        KEY idx_user_id (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");


    // Initial setup: create default admin if no users exist
    $res = $mysqli->query("SELECT COUNT(*) as count FROM users");
    $rowCount = $res ? $res->fetch_assoc()['count'] : 0;
    if ($rowCount == 0) {
        $admin_id = defined('DEFAULT_ADMIN_ID') ? DEFAULT_ADMIN_ID : 'admin';
        $admin_pass = defined('DEFAULT_ADMIN_PASSWORD') ? DEFAULT_ADMIN_PASSWORD : 'adminpass';
        $pass_hash = password_hash($admin_pass, PASSWORD_DEFAULT);
        $expiry = date('Y-m-d H:i:s', strtotime('+10 years'));
        $mysqli->query("INSERT INTO users (employee_id, password, name, user_role, access_mode, expiry_datetime, is_super_admin)
                        VALUES ('$admin_id', '$pass_hash', 'System Admin', 'Admin', 'Paid', '$expiry', 1)");
    }
}

// Helper: Ensure user_skill_groups table exists (id, admin_id, group_name, sort_order)
function ensure_user_groups_table($mysqli) {
    $sql = "CREATE TABLE IF NOT EXISTS user_skill_groups (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        group_name VARCHAR(191) NOT NULL,
        sort_order INT NOT NULL DEFAULT 0,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_admin_group_name (admin_id, group_name),
        KEY idx_admin_sort (admin_id, sort_order)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    @$mysqli->query($sql);
}
// Helper: Ensure user_subaccounts table exists (sub logins under a normal User)
function ensure_user_subaccounts_table($mysqli) {
    // Create table if missing
    $sql = "CREATE TABLE IF NOT EXISTS user_subaccounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        parent_employee_id VARCHAR(64) NOT NULL,
        sub_id VARCHAR(64) NOT NULL,
        sub_name VARCHAR(191) NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        ui_permissions JSON NULL,
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_parent_sub (parent_employee_id, sub_id),
        KEY idx_parent (parent_employee_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
    @$mysqli->query($sql);

    // Self-heal: verify required columns (particularly sub_id) exist; add if missing
    $needAddSubId = true;
    if ($res = @$mysqli->query("SHOW COLUMNS FROM user_subaccounts LIKE 'sub_id'")) {
        if ($res->num_rows > 0) { $needAddSubId = false; }
        $res->close();
    }
    if ($needAddSubId) {
        // Attempt to detect alternate legacy column names
        $legacyCol = null;
        if ($res2 = @$mysqli->query("SHOW COLUMNS FROM user_subaccounts")) {
            while ($c = $res2->fetch_assoc()) {
                $name = $c['Field'];
                if (in_array($name, ['subuser_id','sub_user_id','child_id'])) { $legacyCol = $name; break; }
            }
            $res2->close();
        }
        if ($legacyCol) {
            // Rename legacy column to sub_id
            @$mysqli->query("ALTER TABLE user_subaccounts CHANGE COLUMN `".$legacyCol."` `sub_id` VARCHAR(64) NOT NULL");
        } else {
            // Add missing column and unique key if not present
            @$mysqli->query("ALTER TABLE user_subaccounts ADD COLUMN sub_id VARCHAR(64) NOT NULL AFTER parent_employee_id");
        }
        // Ensure unique key exists
        $hasUnique = false;
        if ($iRes = @$mysqli->query("SHOW INDEX FROM user_subaccounts")) {
            while ($idx = $iRes->fetch_assoc()) {
                if ($idx['Key_name'] === 'uniq_parent_sub') { $hasUnique = true; break; }
            }
            $iRes->close();
        }
        if (!$hasUnique) { @$mysqli->query("ALTER TABLE user_subaccounts ADD UNIQUE KEY uniq_parent_sub (parent_employee_id, sub_id)"); }
    }
}
    // Helper: Ensure column_visibility table exists
    function ensure_column_visibility_table($mysqli) {
        $sql = "CREATE TABLE IF NOT EXISTS column_visibility (
            id INT(11) NOT NULL AUTO_INCREMENT,
            admin_id VARCHAR(50) NOT NULL,
            page VARCHAR(50) NOT NULL DEFAULT 'reports',
            column_key VARCHAR(100) NOT NULL,
            is_visible TINYINT(1) NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            PRIMARY KEY (id),
            UNIQUE KEY unique_admin_page_column (admin_id, page, column_key),
            KEY idx_admin_page (admin_id, page)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
        @$mysqli->query($sql);
    }

// Helper: Ensure noted column exists in checkin_logs
function ensure_noted_column($mysqli) {
    $needNoted = true;
    if ($res = @$mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'noted'")) {
        if ($res->num_rows > 0) { $needNoted = false; }
        $res->close();
    }
    if ($needNoted) {
        @$mysqli->query("ALTER TABLE checkin_logs ADD COLUMN noted TEXT NULL AFTER late_reason");
    }
}
// Helper: Ensure push_subscriptions table exists
function ensure_push_subscriptions_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS push_subscriptions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(50) NOT NULL,
        endpoint TEXT NOT NULL,
        p256dh VARCHAR(255) NOT NULL,
        auth VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY (endpoint(255))
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}
function sendWebPushNotification($mysqli, $target_employee_id, $title, $body) {
    if (!$target_employee_id) return false;
    $sql = "SELECT endpoint, p256dh, auth FROM push_subscriptions WHERE employee_id = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $target_employee_id);
        $stmt->execute();
        $res = $stmt->get_result();
        $subscriptions = [];
        while ($row = $res->fetch_assoc()) {
            $subscriptions[] = \Minishlink\WebPush\Subscription::create([
                'endpoint' => $row['endpoint'],
                'keys' => [
                    'p256dh' => $row['p256dh'],
                    'auth' => $row['auth']
                ]
            ]);
        }
        $stmt->close();
        if (empty($subscriptions)) {
            error_log("[WebPush-Admin] No subscriptions found for: " . $target_employee_id);
            return false;
        }
        error_log("[WebPush-Admin] Found " . count($subscriptions) . " subscriptions for: " . $target_employee_id);
        $auth = [
            'VAPID' => [
                'subject' => 'mailto:admin@vvc-attendance.com',
                'publicKey' => 'BGBSU2jW6Olk8tnMgy_4UsqLajIj3VWy-SLC8A4HswFJkEFvJybNrRKNAYG2LkHM-jQJ6TDVccJ1qLUTW41T-gs',
                'privateKey' => '9t8CytL5CzWUDbGiTrr7KO54kfpVGme-nySjecH9MPah',
            ],
        ];
        try {
            $webPush = new \Minishlink\WebPush\WebPush($auth);
            $payload = json_encode(['title' => $title, 'body' => $body]);
            foreach ($subscriptions as $subscription) { $webPush->queueNotification($subscription, $payload); }
            foreach ($webPush->flush() as $report) {
                if (!$report->isSuccess() && $report->isSubscriptionExpired()) {
                     $mysqli->query("DELETE FROM push_subscriptions WHERE endpoint = '" . $mysqli->real_escape_string($report->getEndpoint()) . "'");
                }
            }
            return true;
        } catch (\Exception $e) { error_log("[WebPush] " . $e->getMessage()); return false; }
    }
    return false;
}
// Helper: Ensure employment_status & leave_date columns exist + user_access_logs table
function ensure_employment_columns_and_logs($mysqli) {
    // Add employment_status if missing
    $needEmployment = true; $needLeaveDate = true;
    if ($res = @$mysqli->query("SHOW COLUMNS FROM users LIKE 'employment_status'")) { if ($res->num_rows>0) { $needEmployment=false; } $res->close(); }
    if ($needEmployment) { @ $mysqli->query("ALTER TABLE users ADD COLUMN employment_status ENUM('Active','Suspended','Resigned') NOT NULL DEFAULT 'Active' AFTER access_mode"); }
    // Add leave_date if missing
    if ($res = @$mysqli->query("SHOW COLUMNS FROM users LIKE 'leave_date'")) { if ($res->num_rows>0) { $needLeaveDate=false; } $res->close(); }
    if ($needLeaveDate) { @ $mysqli->query("ALTER TABLE users ADD COLUMN leave_date DATE NULL AFTER employment_status"); }
    // Ensure access logs table exists
    @ $mysqli->query("CREATE TABLE IF NOT EXISTS user_access_logs (\n        id BIGINT AUTO_INCREMENT PRIMARY KEY,\n        employee_id VARCHAR(64) NOT NULL,\n        event_type VARCHAR(64) NOT NULL,\n        ip_address VARCHAR(64) DEFAULT NULL,\n        user_agent VARCHAR(255) DEFAULT NULL,\n        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,\n        KEY idx_emp_created (employee_id, created_at),\n        KEY idx_event_created (event_type, created_at)\n    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}
// Output buffering and other PHP settings
@ini_set('zlib.output_compression', '1');

ob_start();
// ត្រូវប្រាកដថាគ្មាន Space, BOM, ឬ Output ណាផ្សេងមុនបន្ទាត់នេះទេ!
session_start();
// ===============================================
// DISPLAY ERROR FOR DEBUGGING (បើកសម្រាប់តេស្ត)
// ===============================================
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Configuration is moved to config.php







// ===============================================
// START: កែប្រែ $admin_pages_list
// ===============================================
$admin_pages_list = [
    'dashboard' => ['dashboard' => 'Dashboard (Always Allowed)'],
    'users' => [
        'list_users' => 'បញ្ជីអ្នកប្រើប្រាស់ & កែសម្រួលព័ត៌មាន',
        'create_user' => 'បង្កើតអ្នកប្រើប្រាស់ថ្មី',
        'create_admin' => 'បង្កើតគណនី Admin (សម្រាប់ Super Admin ប៉ុណ្ណោះ)',
        'edit_rules' => 'គ្រប់គ្រងច្បាប់ម៉ោងបុគ្គលិក',
    ],
    'reports' => [
        'reports' => 'របាយការណ៍វត្តមាន',
        'late_report_summary' => 'របាយការណ៍មកយឺតសរុប',
        'forgotten_scan_report' => 'របាយការណ៍ភ្លេចស្កេន',
    ],
    'payroll' => [
        'payroll' => 'Payroll',
    ],
    'requests' => [
        'requests' => 'គ្រប់គ្រងសំណើរ (Manage Requests)',
    ],
    'notifications' => [
        'send_notifications' => 'ផ្ញើការជូនដំណឹងទៅអ្នកប្រើប្រាស់',
    ],
    'locations' => [
        'list_locations' => 'បញ្ជីទីតាំង & QR Codes',
        'create_location' => 'បង្កើតទីតាំងថ្មី',
        'assign_location' => 'កំណត់ទីតាំងបុគ្គលិក',
    ],
    'categories' => [
        'categories' => 'គ្រប់គ្រងប្រភេទ (Folders)',
    ],
    'tokens' => [
        'global_settings' => 'Global Token Settings',
        'active_sessions' => 'បញ្ជី Session សកម្ម',
    ],
    'settings' => [
        'panel_settings' => 'ការកំណត់ Panel (Logo, Title, Theme)',
        'menu_settings' => 'ការកំណត់ Sidebar Menu',
        'login_page_settings' => 'ការកំណត់ Login Page',
        'manage_user_fields' => 'គ្រប់គ្រង Fields អ្នកប្រើប្រាស់',
        'manage_request_fields' => 'គ្រប់គ្រង Fields សំណើរ',
        'manage_app_scan' => 'គ្រប់គ្រង App Scan (scan.php)',
    ]
];
// ===============================================
// END: កែប្រែ $admin_pages_list
// ===============================================


// ===============================================
// 			DATABASE CONNECTION & HELPERS
// ===============================================
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

$mysqli->set_charset("utf8mb4");

if ($mysqli->connect_error) {
	// កំហុសធ្ងន់ធ្ងរ នឹងបង្ហាញសារនេះជំនួសផ្ទាំងសរ
	die("Database Connection Failed: " . $mysqli->connect_error);
}

// 1. Ensure core database tables exist
ensure_core_tables($mysqli);
ensure_employment_columns_and_logs($mysqli);
ensure_noted_column($mysqli);
ensure_user_groups_table($mysqli);
ensure_user_subaccounts_table($mysqli);
ensure_column_visibility_table($mysqli);
ensure_push_subscriptions_table($mysqli);


// Auto resign users whose leave_date has passed (once per page load)
function auto_resign_due_users($mysqli) {
    $due = [];
    if ($res = $mysqli->query("SELECT employee_id FROM users WHERE employment_status IN ('Active','Suspended') AND leave_date IS NOT NULL AND leave_date <= CURDATE()")) {
        while($r=$res->fetch_assoc()){ $due[]=$r['employee_id']; }
        $res->close();
    }
    if ($due) {
        $escaped = array_map([$mysqli,'real_escape_string'],$due);
        $in = "'".implode("','",$escaped)."'";
        $mysqli->query("UPDATE users SET employment_status='Resigned' WHERE employee_id IN ($in)");
        // Revoke tokens for resigned users
        $mysqli->query("DELETE FROM active_tokens WHERE employee_id IN ($in)");
        // Log events
        foreach ($due as $emp) { if ($stmt=$mysqli->prepare("INSERT INTO user_access_logs (employee_id,event_type,ip_address,user_agent) VALUES (?,?,?,?)")) { $ev='auto_resign'; $ip=$_SERVER['REMOTE_ADDR']??''; $ua=substr($_SERVER['HTTP_USER_AGENT']??'',0,250); $stmt->bind_param('ssss',$emp,$ev,$ip,$ua); $stmt->execute(); $stmt->close(); } }
    }
}
auto_resign_due_users($mysqli);

/**
 * NEW: មុខងារបង្កើត Fields ដំបូងសម្រាប់ Admin ថ្មី
 */
function initialize_default_user_fields($mysqli, $adminId) {
    $default_fields = [
        ['department', 'នាយកដ្ឋាន', 'text', 1, 10, 0],
        ['position', 'តួនាទី', 'text', 1, 20, 0],
        ['workplace', 'កន្លែងធ្វើការ', 'text', 0, 30, 1],
        ['branch', 'សាខា', 'text', 0, 40, 1]
    ];

    $sql = "INSERT IGNORE INTO user_form_fields (admin_id, field_key, field_label, field_type, is_required, field_order, is_deletable) VALUES (?, ?, ?, ?, ?, ?, ?)";
    if ($stmt = $mysqli->prepare($sql)) {
        foreach ($default_fields as $field) {
            $stmt->bind_param("ssssiii", $adminId, $field[0], $field[1], $field[2], $field[3], $field[4], $field[5]);
            $stmt->execute();
        }
        $stmt->close();
    }
}


function get_setting($mysqli, $adminId, $key, $default = '') {
    static $settings_cache = [];
    $cache_key = $adminId . '_' . $key;
    if (isset($settings_cache[$cache_key])) return $settings_cache[$cache_key];

    $sql = "SELECT setting_value FROM app_settings WHERE admin_id = ? AND setting_key = ? LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("ss", $adminId, $key);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows > 0) {
            $value = $result->fetch_assoc()['setting_value'];
            $settings_cache[$cache_key] = $value;
            return $value;
        }
    }
    return $default;
}

/**
 * Helper function to save a system-wide setting.
 * @param mysqli $mysqli
 * @param string $key
 * @param string $value
 * @return bool
 */
function update_system_setting($mysqli, $key, $value) {
    $sql = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', ?, ?)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("ss", $key, $value);
        return $stmt->execute();
    }
    return false;
}
// Helper to read admin-specific setting (wrapper)
function get_admin_setting($mysqli, $adminId, $key, $default='') {
    return get_setting($mysqli, $adminId, $key, $default);
}
// Determine if a sidebar item should be hidden based on stored JSON list
function resolveVisibilityOwnerId($mysqli, $accountId) {
    static $map = [];
    if (isset($map[$accountId])) return $map[$accountId];
    $sql = "SELECT user_role, created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param('s', $accountId);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            if ($row['user_role'] === 'Admin') { $map[$accountId] = $accountId; return $accountId; }
            $owner = $row['created_by_admin_id'] ?: $accountId;
            $map[$accountId] = $owner; return $owner;
        }
        $stmt->close();
    }
    return $accountId;
}
function isSidebarHidden($mysqli, $adminId, $pageKey, $actionKey = null) {
    static $cache = [];
    $effectiveAdmin = resolveVisibilityOwnerId($mysqli, $adminId);
    $cacheKey = $effectiveAdmin . '_sidebar_hidden_items';
    if (!isset($cache[$cacheKey])) {
        $json = get_setting($mysqli, $effectiveAdmin, 'sidebar_hidden_items', '[]');
        $arr = json_decode($json, true); if (!is_array($arr)) { $arr=[]; }
        $cache[$cacheKey] = $arr;
    }
    $hidden = $cache[$cacheKey];
    if (in_array($pageKey, $hidden, true)) return true;
    if ($actionKey && in_array($pageKey.'::'.$actionKey, $hidden, true)) return true;
    return false;
}

/**
 * =========================================================================
 * កូដថ្មីสำหรับ STEP 2
 * =========================================================================
 * Helper function to get a setting from the app_scan_settings table FOR A SPECIFIC ADMIN.
 * @param mysqli $mysqli
 * @param string $adminId The ID of the admin whose setting we want
 * @param string $key
 * @param string $default
 * @return string
 */
function get_app_scan_setting($mysqli, $adminId, $key, $default = '') {
    static $app_settings_cache = [];
    $cache_key = $adminId . '_' . $key;

    if (isset($app_settings_cache[$cache_key])) {
        return $app_settings_cache[$cache_key];
    }

    // If there are duplicate rows (legacy), pick the most recent one
    $sql = "SELECT setting_value FROM app_scan_settings WHERE admin_id = ? AND setting_key = ? ORDER BY id DESC LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("ss", $adminId, $key);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result && $result->num_rows > 0) {
            $value = $result->fetch_assoc()['setting_value'];
            $app_settings_cache[$cache_key] = $value;
            return $value;
        }
        $stmt->close();
    }
    return $default;
}

/**
 * Helper function to save a setting to the app_scan_settings table FOR A SPECIFIC ADMIN.
 * @param mysqli $mysqli
 * @param string $adminId The ID of the admin whose setting we are saving
 * @param string $key
 * @param string $value
 * @return bool
 */
function update_app_scan_setting($mysqli, $adminId, $key, $value) {
    // With composite unique key (admin_id, setting_key) in place,
    // use standard upsert to avoid duplicate errors even when value is unchanged.
    $sql = "INSERT INTO app_scan_settings (admin_id, setting_key, setting_value)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("sss", $adminId, $key, $value);
        $ok = $stmt->execute();
        $stmt->close();
        return $ok;
    }
    return false;
}


/**
 * Function to populate sidebar settings for a specific admin if their settings are empty.
 * @param mysqli $mysqli Database connection
 * @param string $adminId The ID of the admin to initialize settings for
 */
function initialize_sidebar_settings($mysqli, $adminId) {
    global $admin_pages_list; // ត្រូវការ Access ទៅ List នេះ

    // 1. ពិនិត្យ និងបង្កើត Main Menu
    $check_sql = "SELECT COUNT(*) as count FROM sidebar_settings WHERE admin_id = ?";
    $stmt_check = $mysqli->prepare($check_sql);
    $stmt_check->bind_param("s", $adminId);
    $stmt_check->execute();
    $result = $stmt_check->get_result();
    $count = $result ? $result->fetch_assoc()['count'] : 0;
    $stmt_check->close();

    if ($count == 0) {
        $default_menu = [
            'dashboard' => ['text' => 'Dashboard', 'icon' => 'fa-solid fa-gauge', 'order' => 10],
            'users' => ['text' => 'គ្រប់គ្រងអ្នកប្រើប្រាស់', 'icon' => 'fa-solid fa-users', 'order' => 20],
            'reports' => ['text' => 'របាយការណ៍វត្តមាន', 'icon' => 'fa-solid fa-chart-simple', 'order' => 30],
            'requests' => ['text' => 'គ្រប់គ្រងសំណើរ', 'icon' => 'fa-solid fa-file-signature', 'order' => 40],
            'notifications' => ['text' => 'ការជូនដំណឹង', 'icon' => 'fa-solid fa-bell', 'order' => 45],
            'locations' => ['text' => 'គ្រប់គ្រងទីតាំង/QR', 'icon' => 'fa-solid fa-map-location-dot', 'order' => 50],
            'categories' => ['text' => 'គ្រប់គ្រងប្រភេទ', 'icon' => 'fa-solid fa-folder-open', 'order' => 60],
            'tokens' => ['text' => 'គ្រប់គ្រង Token & Session', 'icon' => 'fa-solid fa-key', 'order' => 70],
            'settings' => ['text' => 'ការកំណត់', 'icon' => 'fa-solid fa-cogs', 'order' => 80]
        ];

         $sql = "INSERT IGNORE INTO sidebar_settings (admin_id, menu_key, menu_text, icon_class, menu_order) VALUES (?, ?, ?, ?, ?)";
        if ($stmt = $mysqli->prepare($sql)) {
            foreach ($default_menu as $key => $details) {
                $stmt->bind_param("ssssi", $adminId, $key, $details['text'], $details['icon'], $details['order']);
                $stmt->execute();
            }
            $stmt->close();
        }
    }

    // Ensure any new pages added to $admin_pages_list are present for existing admins.
    // This makes the function idempotent and will add newly introduced menu keys like 'payroll'.
    try {
        $existing = [];
        if ($sel = $mysqli->prepare("SELECT menu_key FROM sidebar_settings WHERE admin_id = ?")) {
            $sel->bind_param("s", $adminId);
            $sel->execute();
            $res = $sel->get_result();
            while ($r = $res->fetch_assoc()) { $existing[] = $r['menu_key']; }
            $sel->close();
        }

        $ins = $mysqli->prepare("INSERT IGNORE INTO sidebar_settings (admin_id, menu_key, menu_text, icon_class, menu_order) VALUES (?, ?, ?, ?, ?)");
        if ($ins) {
            foreach ($admin_pages_list as $key => $actions) {
                if (in_array($key, $existing, true)) { continue; }
                $menu_text = ucfirst(str_replace('_',' ',$key));
                $icon = 'fa-solid fa-folder';
                $order = 9999; // put new items at end by default
                $ins->bind_param("ssssi", $adminId, $key, $menu_text, $icon, $order);
                $ins->execute();
            }
            $ins->close();
        }
    } catch (Exception $e) {
        // Non-fatal: keep going
    }

    // --- START: កែសម្រួលសម្រាប់ SUBMENU ---
    // 2. ពិនិត្យ និងបង្កើត Submenu
    $check_submenu_sql = "SELECT COUNT(*) as count FROM submenu_settings WHERE admin_id = ?";
    $stmt_check_submenu = $mysqli->prepare($check_submenu_sql);
    $stmt_check_submenu->bind_param("s", $adminId);
    $stmt_check_submenu->execute();
    $submenu_result = $stmt_check_submenu->get_result();
    $submenu_count = $submenu_result ? $submenu_result->fetch_assoc()['count'] : 0;
    $stmt_check_submenu->close();

    if ($submenu_count == 0) {
        $submenu_sql = "INSERT IGNORE INTO submenu_settings (admin_id, menu_key, action_key, submenu_text) VALUES (?, ?, ?, ?)";
        if ($stmt_submenu = $mysqli->prepare($submenu_sql)) {
            foreach ($admin_pages_list as $menu_key => $actions) {
                // រំលង Menu ដែលគ្មាន Submenu ពិតប្រាកដ
                if (count($actions) <= 1 && isset($actions[$menu_key])) continue;

                foreach ($actions as $action_key => $action_text) {
                    $stmt_submenu->bind_param("ssss", $adminId, $menu_key, $action_key, $action_text);
                    $stmt_submenu->execute();
                }
            }
            $stmt_submenu->close();
        }
    }
    // --- END: កែសម្រួលសម្រាប់ SUBMENU ---
}

// These variables will be defined after successful login or before login page display.
$panel_title = 'Admin Panel'; // Default value
$panel_logo_path = '';
$show_title_with_logo = true;
$footer_text = '';

// ===============================================
// END: DATABASE & SETTINGS HELPERS
// ===============================================


$error = '';
$success = '';
$admin_subscription_warning = ''; // សារព្រមាន Subscription

// --- Helper Functions ---
function checkAdminLogin($mysqli) {
	// ពិនិត្យ Session ថានៅសល់ឬអត់
	return isset($_SESSION['admin_logged_in']) && $_SESSION['admin_logged_in'];
}

// NEW: មុខងារពិនិត្យ Super Admin
function isSuperAdmin() {
    // ពិនិត្យមើល Session ថាតើជា Super Admin ដែរឬទេ
    return isset($_SESSION['is_super_admin']) && $_SESSION['is_super_admin'];
}

/**
 * NEW: មុខងារពិនិត្យសិទ្ធិចូលប្រើប្រាស់ទំព័រសម្រាប់ Admin នីមួយៗ
 * @param mysqli $mysqli Database connection
 * @param string $page The main page key (e.g., 'users', 'reports')
 * @param string $action The subpage/action key (e.g., 'list_users', 'reports')
 * @param string $adminId The employee_id of the admin to check
 * @return bool True if access is granted
 */
function currentIsSubUser() { return isset($_SESSION['sub_user_id']); }
function currentSubUserPermissions() { return $_SESSION['sub_user_permissions'] ?? []; }
function hasPageAccess($mysqli, $page, $action, $adminId) {
    global $admin_pages_list;
    // Super Admin អាចចូលបានទាំងអស់
    if (isSuperAdmin()) { return true; }
    // Dashboard ត្រូវបានអនុញ្ញាតជានិច្ច
    if ($page === 'dashboard') { return true; }
    // ពិនិត្យ Page ធំ
    if (!array_key_exists($page, $admin_pages_list)) { return false; }
    // Subpage សម្រាប់ Super Admin មិនអនុញ្ញាតឱ្យ Admin ធម្មតា
    if (($page === 'users' && $action === 'create_admin')) { return false; }
    // Sub User mode: override with its permission list (simple: allow if page OR action listed)
    if (currentIsSubUser()) {
        $perms = currentSubUserPermissions();
        if (!is_array($perms)) { $perms = []; }
        // Accept either direct page key or action key in permission array
        if (in_array($page, $perms, true) || in_array($action, $perms, true)) { return true; }
        return false; // deny if not explicitly allowed
    }

    // Normal admin: consult DB page_access_settings
    // First, check for exact match
    $sql = "SELECT 1 FROM page_access_settings WHERE employee_id = ? AND page_key = ? AND action_key = ? LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("sss", $adminId, $page, $action);
        $stmt->execute();
        $has_access = ($stmt->get_result()->num_rows > 0);
        $stmt->close();
        if ($has_access) return true;
    }

    // Implicit access for sub-reports: if user has 'reports' -> 'reports' permission,
    // they automatically get access to 'late_report_summary' and 'forgotten_scan_report'.
    if ($page === 'reports' && in_array($action, ['late_report_summary', 'forgotten_scan_report'])) {
        $sql_implicit = "SELECT 1 FROM page_access_settings WHERE employee_id = ? AND page_key = 'reports' AND action_key = 'reports' LIMIT 1";
        if ($stmt_impl = $mysqli->prepare($sql_implicit)) {
            $stmt_impl->bind_param("s", $adminId);
            $stmt_impl->execute();
            $has_impl = ($stmt_impl->get_result()->num_rows > 0);
            $stmt_impl->close();
            if ($has_impl) return true;
        }
    }

    return false; // deny if no match found
}

// NEW: Helper to decide if admin can manage user skill groups (categories)
// Normal Admins: If they have either users create/list permission OR explicit categories access.
// Super Admin: always yes.
function canManageUserGroups($mysqli, $adminId) {
    if (isSuperAdmin()) { return true; }
    // Explicit categories page access
    if (hasPageAccess($mysqli, 'categories', 'categories', $adminId)) { return true; }
    // Implicit via user management capabilities
    if (hasPageAccess($mysqli, 'users', 'create_user', $adminId) || hasPageAccess($mysqli, 'users', 'list_users', $adminId)) { return true; }
    return false;
}

// NEW: Helper to decide if admin can manage time rules (attendance rules)
// Super Admin: always yes
// Normal Admin: allowed if they explicitly have users/edit_rules OR have general user management rights (create/list)
function canManageTimeRules($mysqli, $adminId) {
    if (isSuperAdmin()) { return true; }
    if (hasPageAccess($mysqli, 'users', 'edit_rules', $adminId)) { return true; }
    if (hasPageAccess($mysqli, 'users', 'create_user', $adminId) || hasPageAccess($mysqli, 'users', 'list_users', $adminId)) { return true; }
    return false;
}

// Helper: log user access / lifecycle events
function log_user_event($mysqli, $employee_id, $event_type) {
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 250);
    if (!preg_match('/^[A-Za-z0-9_\-]{1,64}$/', $event_type)) { $event_type = 'unknown'; }
    if ($stmt = $mysqli->prepare("INSERT INTO user_access_logs (employee_id, event_type, ip_address, user_agent) VALUES (?,?,?,?)")) {
        $stmt->bind_param('ssss', $employee_id, $event_type, $ip, $ua);
        $stmt->execute();
        $stmt->close();
    }
}


/**
 * Compress and resize image during upload.
 * Falls back to simple move_uploaded_file if GD is missing or format unsupported.
 */
/**
 * Compresses an image and optionally converts it to WebP.
 * $destination is passed by reference so it can be updated if the extension changes.
 */
function compressAndMoveImage($source, &$destination, $quality = 80, $maxWidth = 1200, $maxHeight = 1200) {
    if (!function_exists('imagecreatefromjpeg')) {
        return move_uploaded_file($source, $destination);
    }

    $info = @getimagesize($source);
    if ($info === false) {
        return move_uploaded_file($source, $destination);
    }

    $mime = $info['mime'];
    $width = $info[0];
    $height = $info[1];

    // Calculate new dimensions maintaining aspect ratio
    $newW = $width;
    $newH = $height;
    if ($width > $maxWidth || $height > $maxHeight) {
        $ratio = $width / $height;
        if ($ratio > 1) {
            $newW = $maxWidth;
            $newH = $maxWidth / $ratio;
        } else {
            $newH = $maxHeight;
            $newW = $maxHeight * $ratio;
        }
    }

    // Load original image
    $image = null;
    switch ($mime) {
        case 'image/jpeg': $image = @imagecreatefromjpeg($source); break;
        case 'image/png':  $image = @imagecreatefrompng($source); break;
        case 'image/gif':  $image = @imagecreatefromgif($source); break;
        case 'image/webp': $image = @imagecreatefromwebp($source); break;
    }

    if (!$image) {
        return move_uploaded_file($source, $destination);
    }

    // Create canvas
    $resampled = imagecreatetruecolor($newW, $newH);

    // Transparency handling
    if ($mime == 'image/png' || $mime == 'image/webp' || $mime == 'image/gif') {
        imagecolortransparent($resampled, imagecolorallocatealpha($resampled, 0, 0, 0, 127));
        imagealphablending($resampled, false);
        imagesavealpha($resampled, true);
    }

    imagecopyresampled($resampled, $image, 0, 0, 0, 0, $newW, $newH, $width, $height);

    // WebP Conversion (Superior compression & quality)
    $success = false;
    if (function_exists('imagewebp')) {
        // Update destination extension to .webp
        $info_p = pathinfo($destination);
        $new_dest = $info_p['dirname'] . DIRECTORY_SEPARATOR . $info_p['filename'] . '.webp';

        // Save as WebP
        if (imagewebp($resampled, $new_dest, $quality)) {
            $destination = $new_dest;
            $success = true;
        }
    }

    // Fallback to original mime if WebP failed or not supported
    if (!$success) {
        switch ($mime) {
            case 'image/jpeg':
                imageinterlace($resampled, 1); // Progressive JPEG
                $success = imagejpeg($resampled, $destination, $quality);
                break;
            case 'image/png':
                $success = imagepng($resampled, $destination, 6);
                break;
            case 'image/gif':
                $success = imagegif($resampled, $destination);
                break;
            case 'image/webp':
                $success = imagewebp($resampled, $destination, $quality);
                break;
            default:
                $success = move_uploaded_file($source, $destination);
        }
    }

    imagedestroy($image);
    imagedestroy($resampled);
    return $success;
}

function hashPassword($password) {
	return password_hash($password ?? ('qr_only_login_' . time()), PASSWORD_DEFAULT);
}

function attemptAdminLogin($mysqli, $id, $password) {
	$id = trim($id);

	// កែប្រែ: បន្ថែម is_super_admin ទៅក្នុង SELECT
	$sql = "SELECT employee_id, name, password, user_role, is_super_admin FROM users WHERE employee_id = ? AND user_role = 'Admin'";

	if ($stmt = $mysqli->prepare($sql)) {
		$stmt->bind_param("s", $id);
		$stmt->execute();
		$result = $stmt->get_result();

		if ($result->num_rows == 1) {
			$user = $result->fetch_assoc();

			if (password_verify($password, $user['password'])) {
				// កំណត់ Session
				$_SESSION['admin_logged_in'] = true;
				$_SESSION['admin_id'] = $user['employee_id'];
				$_SESSION['admin_name'] = $user['name'];
				// NEW: កំណត់ Super Admin Status
                $_SESSION['is_super_admin'] = (bool)$user['is_super_admin'];
                // Log admin login
                log_user_event($mysqli, $user['employee_id'], 'admin_login');
				return true;
			}
		}
	}
	return false;
}

/**
 * Attempt a sub-user login (for normal user acting as a super user of its data scope).
 * Parent normal user credentials are not revalidated here; token flow keeps parent logged in separately.
 * Sub account has limited UI permissions stored in JSON.
 */
function attemptSubUserLogin($mysqli, $parentId, $subId, $passwordPlain) {
    ensure_user_subaccounts_table($mysqli);
    $sql = "SELECT id, sub_id, sub_name, password_hash, ui_permissions FROM user_subaccounts WHERE parent_employee_id = ? AND sub_id = ? LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param('ss', $parentId, $subId);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            if (password_verify($passwordPlain, $row['password_hash'])) {
                $_SESSION['sub_user_logged_in'] = true;
                $_SESSION['sub_user_parent_id'] = $parentId;
                $_SESSION['sub_user_id'] = $row['sub_id'];
                $_SESSION['sub_user_name'] = $row['sub_name'];
                $_SESSION['sub_user_permissions'] = json_decode($row['ui_permissions'] ?? '[]', true);
                // Allow entering the panel: set an admin-like session scoped to parent user
                $_SESSION['admin_logged_in'] = true;
                $_SESSION['admin_id'] = $parentId; // use parent employee_id for scoping
                $_SESSION['admin_name'] = $row['sub_name'] . ' (Sub)';
                $_SESSION['is_super_admin'] = false;
                log_user_event($mysqli, $row['sub_id'], 'sub_user_login');
                return true;
            }
        }
        $stmt->close();
    }
    return false;
}

// NEW: Attempt sub user login using sub_id only (no parent id provided)
function attemptSubUserLoginBySubId($mysqli, $subId, $passwordPlain) {
    ensure_user_subaccounts_table($mysqli);
    if ($stmt = $mysqli->prepare("SELECT parent_employee_id, sub_id, sub_name, password_hash, ui_permissions FROM user_subaccounts WHERE sub_id = ? ORDER BY id ASC LIMIT 2")) {
        $stmt->bind_param('s', $subId);
        $stmt->execute();
        $res = $stmt->get_result();
        $rows = [];
        while ($r = $res->fetch_assoc()) { $rows[] = $r; }
        $stmt->close();
        if (count($rows) === 0) return ['ok'=>false,'reason'=>'not_found'];
        if (count($rows) > 1) return ['ok'=>false,'reason'=>'ambiguous'];
        $row = $rows[0];
        if (!password_verify($passwordPlain, $row['password_hash'])) { return ['ok'=>false,'reason'=>'invalid_password']; }
        // Success: set sessions using resolved parent
        $_SESSION['sub_user_logged_in'] = true;
        $_SESSION['sub_user_parent_id'] = $row['parent_employee_id'];
        $_SESSION['sub_user_id'] = $row['sub_id'];
        $_SESSION['sub_user_name'] = $row['sub_name'];
        $_SESSION['sub_user_permissions'] = json_decode($row['ui_permissions'] ?? '[]', true);
        $_SESSION['admin_logged_in'] = true;
        $_SESSION['admin_id'] = $row['parent_employee_id'];
        $_SESSION['admin_name'] = $row['sub_name'] . ' (Sub)';
        $_SESSION['is_super_admin'] = false;
        return ['ok'=>true];
    }
    return ['ok'=>false,'reason'=>'db_error'];
}

/**
 * មុខងារសម្រាប់ផ្ញើសារទៅកាន់ Telegram (Placeholder Function)
 * @param string $chatId Telegram Chat ID របស់អ្នកប្រើប្រាស់
 * @param string $message សារដែលត្រូវផ្ញើ
 * @return bool True on success, false on failure
 */
function sendTelegramNotification($chatId, $message) {
    if (TELEGRAM_BOT_TOKEN === 'YOUR_TELEGRAM_BOT_TOKEN' || empty($chatId)) {
        // សម្រាប់តេស្ត
        error_log("Telegram Notification Sent (Simulated) to Chat ID: {$chatId}. Message: {$message}");
        return true;
    }

    $url = 'https://api.telegram.org/bot' . TELEGRAM_BOT_TOKEN . '/sendMessage';
    $data = [
        'chat_id' => $chatId,
        'text' => $message,
        'parse_mode' => 'HTML',
    ];

    $options = [
        'http' => [
            'method'  => 'POST',
            'header'  => 'Content-Type: application/x-www-form-urlencoded',
            'content' => http_build_query($data),
        ],
    ];

    // uncomment to enable real telegram sending
    // $context  = stream_context_create($options);
    // $result = @file_get_contents($url, false, $context);

    // return ($result !== false);
    return true; // Return true for simulation
}


/**
 * ពិនិត្យមើលស្ថានភាពចូលប្រើប្រាស់ប្រព័ន្ធ (Subscription Expiry Logic with Time)
 * @param mysqli $mysqli Database connection
 * @param string $adminId Admin ID to check
 * @return array ['status' => 'ok'|'expired'|'warning', 'message' => '...']
 */
function checkAccessExpiry($mysqli, $adminId) {
    // កែប្រែ: ទាញយក expiry_datetime និង expiry_notification_sent
    $sql = "SELECT access_mode, expiry_datetime, telegram_chat_id, expiry_notification_sent FROM users WHERE employee_id = ? AND user_role = 'Admin' LIMIT 1";

    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $adminId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            return ['status' => 'ok', 'message' => 'Cannot find Admin ID. Access granted by default.'];
        }

        $admin = $result->fetch_assoc();
        $expiry_datetime_str = $admin['expiry_datetime'];
        $access_mode = $admin['access_mode'];
        $telegram_chat_id = $admin['telegram_chat_id'];
        $notification_sent = (bool)$admin['expiry_notification_sent'];

        // កំណត់ Timezone ទៅភ្នំពេញ ដើម្បីឱ្យម៉ោង Server ត្រឹមត្រូវ
        date_default_timezone_set('Asia/Phnom_Penh');
        $current_dt = new DateTime();

        if ($access_mode === 'Free') {
            return ['status' => 'ok', 'message' => 'របៀបចូលប្រើ៖ **ឥតគិតថ្លៃ (Free)**។'];
        }

        if ($access_mode === 'Expired' || empty($expiry_datetime_str)) {
            return ['status' => 'expired', 'message' => 'ការចូលប្រើប្រាស់របស់អ្នក **បានផុតកំណត់** ហើយ! សូមបន្តថ្ងៃខែឆ្នាំប្រើប្រាស់។'];
        }

        $expiry_dt = new DateTime($expiry_datetime_str);

        // 1. ពិនិត្យមើលថាផុតកំណត់ហើយឬនៅ (ពិនិត្យទាំងម៉ោង)
        if ($current_dt > $expiry_dt) {
            $expired_message = 'ការចូលប្រើប្រាស់របស់អ្នក **បានផុតកំណត់** នៅថ្ងៃ ' . $expiry_dt->format('d-M-Y H:i:s') . ' ហើយ!';

            // 2. បើផុតកំណត់ ពិនិត្យមើលថាតើបានផ្ញើសារទៅ Telegram ហើយឬនៅ
            if (!$notification_sent && !empty($telegram_chat_id)) {
                $telegram_message = "🔴 **Subscription បានផុតកំណត់**\n\nការចូលប្រើប្រាស់ Admin Panel របស់អ្នកបានផុតកំណត់នៅម៉ោង **" . $expiry_dt->format('d-M-Y H:i:s') . "**។\n\nប្រព័ន្ធបាន Log Out អ្នកដោយស្វ័យប្រវត្តិ។ សូមទាក់ទង Super Admin ដើម្បីបន្ត Subscription។";
                sendTelegramNotification($telegram_chat_id, $telegram_message);
                sendWebPushNotification($mysqli, $adminId, "Subscription Expired", "Admin Panel access expired at " . $expiry_dt->format('d-M-Y H:i:s'));
            }

            // 3. Update Database ទៅជា Expired និងសម្គាល់ថាបានផ្ញើសារហើយ
            $update_sql = "UPDATE users SET access_mode = 'Expired', expiry_notification_sent = 1 WHERE employee_id = ?";
            if ($update_stmt = $mysqli->prepare($update_sql)) {
                $update_stmt->bind_param("s", $adminId);
                $update_stmt->execute();
                $update_stmt->close();
            }

            return ['status' => 'expired', 'message' => $expired_message];
        }

        // 4. ពិនិត្យមើលការព្រមាន (Warning) បើនៅសល់តិចជាង 7 ថ្ងៃ
        $interval = $current_dt->diff($expiry_dt);
        $days_left = (int)$interval->format('%r%a'); // %r សម្រាប់សញ្ញា + ឬ -

        if ($days_left <= 7) {
            // សារព្រមាននេះនៅតែផ្ញើដដែល ដើម្បីឱ្យ Admin ដឹងខ្លួនមុន
            $telegram_warning_message = "🔔 **ការជូនដំណឹងជិតផុតកំណត់**\n\nការចូលប្រើប្រាស់ប្រព័ន្ធ Admin Panel នឹងផុតកំណត់នៅថ្ងៃ **" . $expiry_dt->format('d-M-Y H:i:s') . "** (នៅសល់តែ {$days_left} ថ្ងៃ)។\n\nសូម Log In ចូល Admin Panel ហើយចុចបន្តថ្ងៃខែឆ្នាំប្រើប្រាស់។";

            if (!empty($telegram_chat_id)) {
                // To avoid spamming, this simple logic sends it once a day if they log in.
                // A more complex system would use a cron job.
                sendTelegramNotification($telegram_chat_id, $telegram_warning_message);
                sendWebPushNotification($mysqli, $adminId, "Subscription Warning", "Admin Panel access will expire in {$days_left} days.");
            }

            return ['status' => 'warning', 'message' => "ការចូលប្រើប្រាស់របស់អ្នកនឹងផុតកំណត់ក្នុងរយៈពេល **{$days_left} ថ្ងៃ** (នៅថ្ងៃ " . $expiry_dt->format('d-M-Y H:i:s') . ")។ សូមបន្តប្រើប្រាស់!"];
        }

        // 5. បើមិនទាន់ផុតកំណត់ និងមិនទាន់ដល់ពេលព្រមាន
        return ['status' => 'ok', 'message' => "របៀបចូលប្រើ៖ **{$access_mode}**។ នឹងផុតកំណត់នៅថ្ងៃ " . $expiry_dt->format('d-M-Y H:i:s') . " (នៅសល់ {$days_left} ថ្ងៃ)"];
    }
    return ['status' => 'ok', 'message' => 'Database error on access check.']; // Access granted by default on DB error
}


/**
 * គណនាចម្ងាយរវាង Latitude/Longitude ពីរដោយใช้ Haversine Formula۔
 */
function calculateDistance($lat1, $lon1, $lat2, $lon2) {
    $earth_radius = 6371000;
    $dLat = deg2rad($lat2 - $lat1);
    $dLon = deg2rad($lon2 - $lon1);
    $a = sin($dLat/2) * sin($dLat/2) +
            cos(deg2rad($lat1)) * cos(deg2rad($lat2)) * sin($dLon/2) * sin($dLon/2);
    $c = 2 * atan2(sqrt($a), sqrt(1-$a));
    $distance = $earth_radius * $c;
    return $distance;
}

/**
 * Format late minutes to a concise human-readable label (e.g. "5m", "1h 15m").
 *
 * @param int|null $minutes
 * @return string
 */
function format_late_minutes($minutes) {
    $m = (int)($minutes ?? 0);
    if ($m <= 0) {
        return '0m';
    }
    if ($m < 60) {
        return $m . 'm';
    }
    $h = intdiv($m, 60);
    $rem = $m % 60;
    if ($rem === 0) {
        return $h . 'h';
    }
    return $h . 'h ' . $rem . 'm';
}


// ពិនិត្យមើលថាតើមាន Admin ក្នុងប្រព័ន្ធឬអត់ (ត្រូវប្រើនៅទីនេះផង)
$admin_count = 0;
if ($result = $mysqli->query("SELECT COUNT(*) as count FROM users WHERE user_role = 'Admin'")) {
	$admin_count = $result->fetch_assoc()['count'];
	$result->close();
}

// ----------------------------------------------------
// PURE POST HANDLER BLOCK (សម្រាប់ Login និង Initial Setup)
// ----------------------------------------------------

if ($_SERVER["REQUEST_METHOD"] == "POST" && !isset($_POST['ajax_action'])) {

	// 1. Initial Setup Handler (បើមិនទាន់មាន Admin)
	if ($admin_count == 0 && isset($_POST['initial_admin_register'])) {
		$admin_id = trim($_POST['admin_id'] ?? '');
		$admin_pass_plain = $_POST['admin_password'] ?? '';
		$admin_name = trim($_POST['admin_name'] ?? '');

		if (!empty($admin_id) && !empty($admin_pass_plain) && !empty($admin_name)) {
			$admin_pass = hashPassword($admin_pass_plain);
			// កែប្រែ៖ ប្រើ expiry_datetime
			$initial_expiry_datetime = date('Y-m-d H:i:s', strtotime('+1 year'));
			$sql = "INSERT INTO users (employee_id, password, name, user_role, access_mode, expiry_datetime, is_super_admin, created_by_admin_id) VALUES (?, ?, ?, 'Admin', 'Paid', ?, TRUE, NULL)";

			if ($stmt = $mysqli->prepare($sql)) {
				$stmt->bind_param("sssss", $admin_id, $admin_pass, $admin_name, $initial_expiry_datetime);
				if ($stmt->execute()) {
                    initialize_sidebar_settings($mysqli, $admin_id);
                    initialize_default_user_fields($mysqli, $admin_id); // NEW: បង្កើត Fields ដំបូង
					// បន្ទាប់ពី Setup ជោគជ័យ ព្យាយាម Login ភ្លាមៗ
					if (attemptAdminLogin($mysqli, $admin_id, $admin_pass_plain)) {
						ob_end_clean();
						header("Location: admin_attendance.php?page=dashboard");
						exit;
					} else {
						$success = "គណនី Admin ដំបូងត្រូវបានបង្កើតដោយជោគជ័យ! សូមចូលប្រើ Admin ID នោះ។";
					}
				} else {
					$error = "មានកំហុសក្នុងការបង្កើត Admin ដំបូង: " . $stmt->error;
				}
				$stmt->close();
			} else {
				$error = "Database error: " . $mysqli->error;
			}
		} else {
			$error = "សូមបំពេញគ្រប់ទិន្នន័យទាំងអស់សម្រាប់ Admin ដំបូង!";
		}
	}

    // 2. Sub User Login via normal POST (no AJAX)
    elseif ($admin_count > 0 && isset($_POST['sub_user_login'])) {
        $parent_emp = trim($_POST['parent_employee_id'] ?? '');
        $sub_id = trim($_POST['sub_id'] ?? '');
        $sub_pass = $_POST['sub_password'] ?? '';
        $vvc_flag = isset($_POST['vvc']) ? 1 : 0; // Capture Vvc checkbox if present

        if ($sub_id === '' || $sub_pass === '') {
            $error = 'សូមបំពេញ Sub ID និង Sub Password';
        } else {
            if ($parent_emp === '') {
                $res = attemptSubUserLoginBySubId($mysqli, $sub_id, $sub_pass);
                if (!empty($res['ok'])) {
                    // preserve Vvc flag in session for later use if needed
                    $_SESSION['sub_user_vvc'] = $vvc_flag;
                    ob_end_clean();
                    header("Location: admin_attendance.php?page=dashboard");
                    exit;
                } else {
                    if (($res['reason'] ?? '') === 'ambiguous') { $error = 'Sub ID មានច្រើន Parent (ពិបាកកំណត់)'; }
                    elseif (($res['reason'] ?? '') === 'not_found') { $error = 'Sub ID មិនមាន'; }
                    elseif (($res['reason'] ?? '') === 'invalid_password') { $error = 'ពាក្យសម្ងាត់មិនត្រឹមត្រូវ'; }
                    else { $error = 'Sub User Login បរាជ័យ'; }
                }
            } else {
                if (attemptSubUserLogin($mysqli, $parent_emp, $sub_id, $sub_pass)) {
                    // preserve Vvc flag in session for later use if needed
                    $_SESSION['sub_user_vvc'] = $vvc_flag;
                    ob_end_clean();
                    header("Location: admin_attendance.php?page=dashboard");
                    exit;
                } else {
                    $error = 'Invalid sub user credentials';
                }
            }
        }
    }

    // 3. Standard Admin Login Handler (បើមាន Admin រួចហើយ)
    elseif ($admin_count > 0 && isset($_POST['admin_login'])) {
		$id = $_POST['employee_id'] ?? '';
		$pass = $_POST['password'] ?? '';

            // Deprecated combined mode flag from AJAX sub login flow (kept for backward compatibility)
            $subFlag = isset($_POST['sub_user_logged_in']) && $_POST['sub_user_logged_in'] === '1';

            if (attemptAdminLogin($mysqli, $id, $pass)) {
                // If a sub user was logged in beforehand, keep its session values (attemptAdminLogin won't clear them) but mark a combined mode flag.
                if ($subFlag && isset($_SESSION['sub_user_id'])) {
                    $_SESSION['combined_admin_sub_mode'] = true; // marker for UI adjustments if needed
                }
			// Check Access Expiry AFTER successful login
			$access_check = checkAccessExpiry($mysqli, $_SESSION['admin_id']);

			if ($access_check['status'] === 'expired') {
				// Log out the user or restrict access
				unset($_SESSION['admin_logged_in']);
                unset($_SESSION['is_super_admin']); // លុប Session ថ្មី
				session_destroy();
				$error = $access_check['message'] . " ការចូលត្រូវបានបដិសេធ!";
			} else {
                // If "Remember Admin" checkbox was checked, create a persistent token + cookie
                if (!empty($_POST['remember_admin'])) {
                    // Ensure auth_tokens table exists (idempotent)
                    $create_sql = "CREATE TABLE IF NOT EXISTS auth_tokens (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        selector VARCHAR(64) NOT NULL UNIQUE,
                        hashed_validator VARCHAR(255) NOT NULL,
                        user_id VARCHAR(64) NOT NULL,
                        expires DATETIME NOT NULL,
                        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                        KEY idx_user_id (user_id)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
                    @$mysqli->query($create_sql);

                    try {
                        $selector = bin2hex(random_bytes(16));
                        $validator = bin2hex(random_bytes(32));
                        $hashed_validator = hash('sha256', $validator);
                        $expires_dt = date('Y-m-d H:i:s', strtotime('+30 days'));
                        if ($stmt_token = $mysqli->prepare("INSERT INTO auth_tokens (selector, hashed_validator, user_id, expires) VALUES (?, ?, ?, ?)")) {
                            $stmt_token->bind_param('ssss', $selector, $hashed_validator, $_SESSION['admin_id'], $expires_dt);
                            $stmt_token->execute();
                            $stmt_token->close();
                        }

                        // Set secure, HttpOnly cookie for admin remember (30 days)
                        setcookie('remember_admin', $selector . ':' . $validator, time() + 60*60*24*30, '/', '', isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off', true);
                    } catch (Exception $e) {
                        // ignore token creation errors (login still succeeds)
                    }
                }

                // Login ជោគជ័យ, Redirect ទៅ Dashboard
                ob_end_clean();
                header("Location: admin_attendance.php?page=dashboard");
                exit;
			}
        } else {
            $error = 'លេខសម្គាល់ ឬពាក្យសម្ងាត់ Admin មិនត្រឹមត្រូវ!';
        }
	}
}

// ----------------------------------------------------
// AJAX HANDLER BLOCK (សម្រាប់ Admin Actions)
// ----------------------------------------------------
if (isset($_POST['ajax_action'])) {
	// សំអាត Output Buffer មុន Output JSON
	ob_clean();

	header('Content-Type: application/json');
	$response = ['status' => 'error', 'message' => 'Internal Server Error'];
	$action = $_POST['ajax_action'];
	$is_logged_in = checkAdminLogin($mysqli);

	$is_super_admin = isSuperAdmin(); // កំណត់តម្លៃឱ្យអថេរ $is_super_admin នៅទីនេះ
	$can_manage_admin = isSuperAdmin(); // រក្សាទុកកូដនេះដដែល
    $current_admin_id = $_SESSION['admin_id'] ?? null;
    // FIX: Define $admin_id_check used later in hasPageAccess() checks (avoid undefined variable)
    $admin_id_check = $current_admin_id;

	// Admin Actions (Requires Login)
	if ($is_logged_in && $current_admin_id) {
		switch ($action) {
            case 'get_column_visibility':
                // Return column visibility for this admin on reports page
                ensure_column_visibility_table($mysqli);
                $cols = [];
                $sqlv = "SELECT column_key, is_visible FROM column_visibility WHERE admin_id = ? AND page = 'reports'";
                if ($stmtv = $mysqli->prepare($sqlv)) {
                    $stmtv->bind_param('s', $current_admin_id);
                    $stmtv->execute();
                    $resv = $stmtv->get_result();
                    while ($r = $resv->fetch_assoc()) { $cols[$r['column_key']] = (int)$r['is_visible']; }
                    $stmtv->close();
                }
                $response = ['status' => 'success', 'data' => $cols];
                break;

            case 'save_column_visibility':
                // Save posted visibility map, expects visibility as JSON object or array of key=>0/1
                ensure_column_visibility_table($mysqli);
                $raw = $_POST['visibility'] ?? null;
                if (is_string($raw)) {
                    $map = json_decode($raw, true);
                } else {
                    $map = $raw;
                }
                if (!is_array($map)) { $response = ['status'=>'error','message'=>'Invalid payload']; break; }

                $okCount = 0; $errMsg = '';
                $ins = $mysqli->prepare("INSERT INTO column_visibility (admin_id, page, column_key, is_visible) VALUES (?, 'reports', ?, ?) ON DUPLICATE KEY UPDATE is_visible = VALUES(is_visible)");
                if (!$ins) { $response = ['status'=>'error','message'=>'DB prepare failed: '.$mysqli->error]; break; }
                foreach ($map as $col => $vis) {
                    $vis = (int)($vis ? 1 : 0);
                    $ins->bind_param('ssi', $current_admin_id, $col, $vis);
                    if ($ins->execute()) { $okCount++; } else { $errMsg .= $ins->error . ' '; }
                }
                $ins->close();
                $response = ['status' => 'success', 'message' => "Saved {$okCount} columns", 'errors' => trim($errMsg)];
                break;
            case 'get_request_counts':
                // Return counts of requests by status for the current admin scope
                $data = ['Pending' => 0, 'Approved' => 0, 'Rejected' => 0];
                if ($is_super_admin) {
                    $sql = "SELECT request_status, COUNT(*) as cnt FROM requests_logs GROUP BY request_status";
                    if ($stmt_counts = $mysqli->prepare($sql)) {
                        $stmt_counts->execute();
                        $res = $stmt_counts->get_result();
                        if ($res) {
                            while ($row = $res->fetch_assoc()) {
                                $status = $row['request_status'];
                                $count = (int)$row['cnt'];
                                if (isset($data[$status])) { $data[$status] = $count; }
                            }
                        }
                        $stmt_counts->close();
                    }
                } else {
                    // Scope by users created by this admin
                    $sql = "SELECT rl.request_status, COUNT(*) as cnt
                            FROM requests_logs rl
                            JOIN users u ON rl.employee_id = u.employee_id
                            WHERE u.created_by_admin_id = ?
                            GROUP BY rl.request_status";
                    if ($stmt_counts = $mysqli->prepare($sql)) {
                        $stmt_counts->bind_param('s', $current_admin_id);
                        $stmt_counts->execute();
                        $res = $stmt_counts->get_result();
                        if ($res) {
                            while ($row = $res->fetch_assoc()) {
                                $status = $row['request_status'];
                                $count = (int)$row['cnt'];
                                if (isset($data[$status])) { $data[$status] = $count; }
                            }
                        }
                        $stmt_counts->close();
                    }
                }
                $response = ['status' => 'success', 'data' => $data];
                break;
            case 'update_late_reason':
                $log_id = (int)($_POST['log_id'] ?? 0);
                $emp_id = trim($_POST['employee_id'] ?? '');
                $log_dt = trim($_POST['log_datetime'] ?? '');
                $late_reason = trim($_POST['late_reason'] ?? '');
                if (empty($log_id) && (empty($emp_id) || empty($log_dt))) { $response = ['status' => 'error', 'message' => 'Missing keys to identify log.']; break; }

                // Detect primary key column for checkin_logs safely
                $pk = 'id';
                $cols = $mysqli->query("SHOW COLUMNS FROM `checkin_logs`");
                if ($cols) {
                    while ($c = $cols->fetch_assoc()) {
                        if (!empty($c['Key']) && strtoupper($c['Key']) === 'PRI') { $pk = $c['Field']; break; }
                    }
                    $cols->close();
                }

                // Permission: only logs of users under this admin (or super admin)
                $check_sql = "SELECT cl.`{$pk}` FROM checkin_logs cl JOIN users u ON cl.employee_id = u.employee_id WHERE cl.`{$pk}` = ?";
                $types = 'i'; $params = [$log_id];
                if (!$is_super_admin) { $check_sql .= " AND u.created_by_admin_id = ?"; $types .= 's'; $params[] = $current_admin_id; }
                if ($stmt = $mysqli->prepare($check_sql)) {
                    $stmt->bind_param($types, ...$params);
                    $stmt->execute();
                    $r = $stmt->get_result();
                    $ok = $r && $r->num_rows > 0; $stmt->close();
                    if (!$ok) { $response = ['status' => 'error', 'message' => 'Permission denied or log not found.']; break; }
                } else { $response = ['status' => 'error', 'message' => 'DB Prepare failed: ' . $mysqli->error]; break; }

                if ($log_id) {
                    $upd = $mysqli->prepare("UPDATE checkin_logs SET late_reason = ? WHERE `{$pk}` = ?");
                    if (!$upd) { $response = ['status' => 'error', 'message' => 'DB Prepare failed: ' . $mysqli->error]; break; }
                    $upd->bind_param('si', $late_reason, $log_id);
                } else {
                    $upd = $mysqli->prepare("UPDATE checkin_logs SET late_reason = ? WHERE employee_id = ? AND log_datetime = ?");
                    if (!$upd) { $response = ['status' => 'error', 'message' => 'DB Prepare failed: ' . $mysqli->error]; break; }
                    $upd->bind_param('sss', $late_reason, $emp_id, $log_dt);
                }
                if ($upd->execute()) { $response = ['status' => 'success', 'message' => 'Late reason updated successfully.']; }
                else { $response = ['status' => 'error', 'message' => 'Update failed: ' . $upd->error]; }
                $upd->close();
                break;
            case 'update_noted':
                $log_id = (int)($_POST['log_id'] ?? 0);
                $noted = trim($_POST['noted'] ?? '');
                if (empty($log_id)) { $response = ['status' => 'error', 'message' => 'Missing log_id.']; break; }

                // Detect primary key column for checkin_logs safely
                $pk = 'id';
                $cols = $mysqli->query("SHOW COLUMNS FROM `checkin_logs`");
                if ($cols) {
                    while ($c = $cols->fetch_assoc()) {
                        if (!empty($c['Key']) && strtoupper($c['Key']) === 'PRI') { $pk = $c['Field']; break; }
                    }
                    $cols->close();
                }

                // Permission: only logs of users under this admin (or super admin)
                $check_sql = "SELECT cl.`{$pk}` FROM checkin_logs cl JOIN users u ON cl.employee_id = u.employee_id WHERE cl.`{$pk}` = ?";
                $types = 'i'; $params = [$log_id];
                if (!$is_super_admin) { $check_sql .= " AND u.created_by_admin_id = ?"; $types .= 's'; $params[] = $current_admin_id; }
                if ($stmt = $mysqli->prepare($check_sql)) {
                    $stmt->bind_param($types, ...$params);
                    $stmt->execute();
                    $r = $stmt->get_result();
                    $ok = $r && $r->num_rows > 0; $stmt->close();
                    if (!$ok) { $response = ['status' => 'error', 'message' => 'Permission denied or log not found.']; break; }
                } else { $response = ['status' => 'error', 'message' => 'DB Prepare failed: ' . $mysqli->error]; break; }

                $upd = $mysqli->prepare("UPDATE checkin_logs SET noted = ? WHERE `{$pk}` = ?");
                if (!$upd) { $response = ['status' => 'error', 'message' => 'DB Prepare failed: ' . $mysqli->error]; break; }
                $upd->bind_param('si', $noted, $log_id);
                if ($upd->execute()) { $response = ['status' => 'success', 'message' => 'Noted updated successfully.']; }
                else { $response = ['status' => 'error', 'message' => 'Update failed: ' . $upd->error]; }
                $upd->close();
                break;

            case 'proxy_fetch':
                // Proxy a GET request to a whitelisted external host to avoid CORS in the browser.
                // Input: POST 'target' (full URL). Only allowed hosts listed below will be fetched.
                $target = trim($_POST['target'] ?? '');
                $allowed_hosts = ['ab.reasonlabsapi.com'];
                if ($target === '') { $response = ['status'=>'error','message'=>'Missing target']; break; }
                $parts = parse_url($target);
                $host = $parts['host'] ?? '';
                if (!in_array($host, $allowed_hosts, true)) { $response = ['status'=>'error','message'=>'Host not allowed']; break; }

                // Perform server-side GET
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $target);
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 15);
                // If remote requires specific headers, set them here. Example: curl_setopt($ch, CURLOPT_HTTPHEADER, ['Accept: application/json']);
                $body = curl_exec($ch);
                $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
                $err = curl_error($ch);
                curl_close($ch);

                if ($body === false || $http_code >= 400) {
                    $response = ['status'=>'error','message'=>'Remote fetch failed','http_code'=>$http_code,'error'=>$err];
                } else {
                    // Return raw body (may be JSON or other). We'll wrap into success response.
                    $response = ['status'=>'success','http_code'=>$http_code,'body'=>$body];
                }
                break;
                case 'add_sub_user':
                    // Normal user (non-admin) acts as parent; super admin/admin can also create on behalf if providing parent_employee_id.
                    ensure_user_subaccounts_table($mysqli);
                    $parent_emp = trim($_POST['parent_employee_id'] ?? ($_SESSION['admin_id'] ?? ''));
                    $sub_id = trim($_POST['sub_id'] ?? '');
                    $sub_name = trim($_POST['sub_name'] ?? '');
                    $sub_pass = $_POST['sub_password'] ?? '';
                    $ui_perms = $_POST['ui_permissions_json'] ?? '[]';
                    if ($parent_emp === '' || $sub_id === '' || $sub_name === '' || $sub_pass === '') {
                        $response = ['status'=>'error','message'=>'Incomplete sub user data'];
                        break;
                    }
                    // Prevent admin id collision with real users
                    if ($stmt=$mysqli->prepare('SELECT 1 FROM user_subaccounts WHERE parent_employee_id = ? AND sub_id = ?')) {
                        $stmt->bind_param('ss',$parent_emp,$sub_id);$stmt->execute();$r=$stmt->get_result();
                        if($r && $r->num_rows>0){$response=['status'=>'error','message'=>'Sub ID already exists under this parent'];$stmt->close();break;}
                        $stmt->close();
                    }
                    $hash=password_hash($sub_pass,PASSWORD_DEFAULT);
                    if($ins=$mysqli->prepare('INSERT INTO user_subaccounts (parent_employee_id, sub_id, sub_name, password_hash, ui_permissions) VALUES (?,?,?,?,?)')){
                        $ins->bind_param('sssss',$parent_emp,$sub_id,$sub_name,$hash,$ui_perms);
                        if($ins->execute()){$response=['status'=>'success','message'=>'Sub user created','sub_id'=>$sub_id];}else{$response=['status'=>'error','message'=>'Insert failed: '.$ins->error];}
                        $ins->close();
                    }else{$response=['status'=>'error','message'=>'DB prepare error: '.$mysqli->error];}
                    break;

                case 'list_sub_users':
                    ensure_user_subaccounts_table($mysqli);
                    $parent_emp = trim($_POST['parent_employee_id'] ?? ($_SESSION['admin_id'] ?? ''));
                    $rows=[];
                    if($sel=$mysqli->prepare('SELECT sub_id, sub_name, ui_permissions, created_at FROM user_subaccounts WHERE parent_employee_id = ? ORDER BY id DESC')){
                        $sel->bind_param('s',$parent_emp);$sel->execute();$res=$sel->get_result();
                        while($row=$res->fetch_assoc()){$row['ui_permissions']=json_decode($row['ui_permissions']??'[]',true);$rows[]=$row;}
                        $sel->close();
                        $response=['status'=>'success','data'=>$rows];
                    }else{$response=['status'=>'error','message'=>'DB error: '.$mysqli->error];}
                    break;

                case 'delete_sub_user':
                    ensure_user_subaccounts_table($mysqli);
                    $parent_emp = trim($_POST['parent_employee_id'] ?? ($_SESSION['admin_id'] ?? ''));
                    $sub_id = trim($_POST['sub_id'] ?? '');
                    if($parent_emp===''||$sub_id===''){ $response=['status'=>'error','message'=>'Missing parent or sub id']; break; }
                    if($del=$mysqli->prepare('DELETE FROM user_subaccounts WHERE parent_employee_id = ? AND sub_id = ? LIMIT 1')){
                        $del->bind_param('ss',$parent_emp,$sub_id);$del->execute();
                        $response = ['status'=>($del->affected_rows>0?'success':'error'),'message'=>($del->affected_rows>0?'Deleted':'Not found or no permission')];
                        $del->close();
                    }else{$response=['status'=>'error','message'=>'DB prepare error: '.$mysqli->error];}
                    break;

            case 'save_push_subscription':
                ensure_push_subscriptions_table($mysqli);
                $sub = json_decode($_POST['subscription'] ?? '{}', true);
                if ($sub && isset($sub['endpoint'])) {
                    $sql = "INSERT INTO push_subscriptions (employee_id, endpoint, p256dh, auth)
                            VALUES (?, ?, ?, ?)
                            ON DUPLICATE KEY UPDATE employee_id = VALUES(employee_id), p256dh = VALUES(p256dh), auth = VALUES(auth)";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("ssss", $_SESSION['admin_id'], $sub['endpoint'], $sub['keys']['p256dh'], $sub['keys']['auth']);
                        $stmt->execute();
                        $stmt->close();
                        $response = ['status' => 'success'];
                    }
                }
                break;

                case 'sub_user_login':
                    ensure_user_subaccounts_table($mysqli);
                    $parent_emp = trim($_POST['parent_employee_id'] ?? '');
                    $sub_id = trim($_POST['sub_id'] ?? '');
                    $sub_pass = $_POST['sub_password'] ?? '';
                    $vvc_flag = isset($_POST['vvc']) ? 1 : 0;
                    if($sub_id===''||$sub_pass===''){ $response=['status'=>'error','message'=>'Missing Sub ID or Password']; break; }
                    if($parent_emp==='') {
                        // Try sub-only login
                        $res = attemptSubUserLoginBySubId($mysqli,$sub_id,$sub_pass);
                        if($res['ok']){
                            // preserve Vvc flag in session and include in response
                            $_SESSION['sub_user_vvc'] = $vvc_flag;
                            $response=['status'=>'success','message'=>'Sub user login success','sub'=>[
                                'id'=>$_SESSION['sub_user_id'],
                                'name'=>$_SESSION['sub_user_name'],
                                'permissions'=>$_SESSION['sub_user_permissions'],
                                'vvc' => (int)$vvc_flag
                            ]];
                        } else {
                            $msg = 'Invalid sub user credentials';
                            if($res['reason']==='ambiguous') $msg='Sub ID មានច្រើន Parent (ពិបាកកំណត់)';
                            if($res['reason']==='not_found') $msg='Sub ID មិនមាន';
                            $response=['status'=>'error','message'=>$msg];
                        }
                    } else {
                        if(attemptSubUserLogin($mysqli,$parent_emp,$sub_id,$sub_pass)){
                            $_SESSION['sub_user_vvc'] = $vvc_flag;
                            $response=['status'=>'success','message'=>'Sub user login success','sub'=>[
                                'id'=>$_SESSION['sub_user_id'],
                                'name'=>$_SESSION['sub_user_name'],
                                'permissions'=>$_SESSION['sub_user_permissions'],
                                'vvc' => (int)$vvc_flag
                            ]];
                        } else { $response=['status'=>'error','message'=>'Invalid sub user credentials']; }
                    }
                    break;

			case 'save_admin_page_access':
				if (!$can_manage_admin) {
					$response = ['status' => 'error', 'message' => "អ្នកមិនមែនជា Super Admin! មិនមានសិទ្ធិចូលប្រើមុខងារនេះទេ។"];
					break;
				}

				$target_admin_id = trim($_POST['target_admin_id'] ?? '');
				$allowed_actions = $_POST['allowed_actions'] ?? [];

				if (empty($target_admin_id)) {
					$response = ['status' => 'error', 'message' => "មិនមាន Admin ID គោលដៅទេ។"];
					break;
				}

				$mysqli->query("DELETE FROM page_access_settings WHERE employee_id = '{$mysqli->real_escape_string($target_admin_id)}'");

				$sql = "INSERT INTO page_access_settings (employee_id, page_key, action_key) VALUES (?, ?, ?)";
				$success_count = 0;
				if ($stmt = $mysqli->prepare($sql)) {

                    global $admin_pages_list;
                    $page_action_map = [];
                    foreach ($admin_pages_list as $page_key => $actions) {
                        foreach ($actions as $action_key => $name) {
                            $page_action_map[$action_key] = $page_key;
                        }
                    }

					foreach ($allowed_actions as $action_key) {
                        $page_key = $page_action_map[$action_key] ?? null;

                        if (!$page_key || ($page_key === 'users' && $action_key === 'create_admin')) {
                            continue;
                        }
                        if ($page_key === 'dashboard') continue;

						$stmt->bind_param("sss", $target_admin_id, $page_key, $action_key);
						if ($stmt->execute()) {
							$success_count++;
						}
					}
					$stmt->close();
					$response = ['status' => 'success', 'message' => "បានរក្សាទុកការកំណត់សិទ្ធិចូលប្រើប្រាស់ចំនួន **{$success_count}** សម្រាប់ Admin {$target_admin_id} ដោយជោគជ័យ!"];
				} else {
					$response = ['status' => 'error', 'message' => "មានកំហុស Database ពេលបញ្ចូល: " . $mysqli->error];
				}
				break;

			case 'update_admin_subscription_settings':
            	if (!$can_manage_admin) {
					$response = ['status' => 'error', 'message' => "អ្នកមិនមែនជា Super Admin! មិនមានសិទ្ធិកែប្រែ Subscription នេះទេ។"];
					break;
				}

				$target_admin_id = trim($_POST['target_admin_id'] ?? '');
                $new_mode = trim($_POST['access_mode'] ?? 'Free');
                $new_expiry_datetime_str = trim($_POST['expiry_datetime'] ?? null);
                $new_telegram_chat_id = trim($_POST['telegram_chat_id'] ?? null);

				if (empty($target_admin_id)) {
					$response = ['status' => 'error', 'message' => "មិនមាន Admin ID គោលដៅទេ។"];
					break;
				}

                if ($new_mode === 'Paid' && empty($new_expiry_datetime_str)) {
                    $response = ['status' => 'error', 'message' => "របៀប Paid តម្រូវឱ្យមានថ្ងៃ និងម៉ោងផុតកំណត់!"];
                    break;
                }

                $expiry_datetime_sql = $new_expiry_datetime_str ? "'" . $mysqli->real_escape_string(date('Y-m-d H:i:s', strtotime($new_expiry_datetime_str))) . "'" : "NULL";

                $sql = "UPDATE users SET
                            access_mode = ?,
                            expiry_datetime = {$expiry_datetime_sql},
                            telegram_chat_id = ?,
                            expiry_notification_sent = 0
                        WHERE employee_id = ?";

                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("sss", $new_mode, $new_telegram_chat_id, $target_admin_id);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "ការកំណត់សិទ្ធិចូលប្រើប្រាស់សម្រាប់ Admin {$target_admin_id} ត្រូវបានរក្សាទុកដោយជោគជ័យ!"];
                    } else {
                        $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការរក្សាទុក: " . $stmt->error];
                    }
                    $stmt->close();
                } else {
                    $response = ['status' => 'error', 'message' => "Database error: " . $mysqli->error];
                }
                break;

            case 'extend_admin_subscription':
            	if (!isSuperAdmin()) {
					$response = ['status' => 'error', 'message' => "អ្នកមិនមែនជា Super Admin! មិនមានសិទ្ធិបន្ត Subscription នេះទេ។"];
					break;
				}

				$target_admin_id = trim($_POST['target_admin_id'] ?? '');
                $days_to_add = (int)($_POST['days_to_add'] ?? 365);

                $current_date_query = $mysqli->query("SELECT expiry_datetime FROM users WHERE employee_id = '{$target_admin_id}' LIMIT 1");
                $current_date_row = $current_date_query->fetch_assoc();
                $current_expiry_datetime = $current_date_row['expiry_datetime'] ?? null;

                date_default_timezone_set('Asia/Phnom_Penh');
                $now = new DateTime();
                $base_dt = $now;

                if ($current_expiry_datetime) {
                    $current_expiry_dt = new DateTime($current_expiry_datetime);
                    if ($current_expiry_dt > $now) {
                        $base_dt = $current_expiry_dt;
                    }
                }

                $base_dt->modify("+{$days_to_add} days");
                $new_expiry_datetime = $base_dt->format('Y-m-d H:i:s');

                $sql = "UPDATE users SET expiry_datetime = ?, access_mode = 'Paid', expiry_notification_sent = 0 WHERE employee_id = ?";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("ss", $new_expiry_datetime, $target_admin_id);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "ថ្ងៃផុតកំណត់សម្រាប់ Admin {$target_admin_id} ត្រូវបានបន្ត **{$days_to_add} ថ្ងៃ** (រហូតដល់ថ្ងៃ {$new_expiry_datetime}) ដោយជោគជ័យ!"];
                    } else {
                        $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការបន្ត: " . $stmt->error];
                    }
                    $stmt->close();
                } else {
                    $response = ['status' => 'error', 'message' => "Database error: " . $mysqli->error];
                }
                break;

            case 'add_user':
                $new_id = trim($_POST['new_id'] ?? '');
                $new_name = trim($_POST['new_name'] ?? '');
                $new_group_id = (int)($_POST['group_id'] ?? 0); // optional skill group
                $custom_data_array = $_POST['custom'] ?? [];

                // If an avatar file was uploaded, move it and add path to custom data
                if (!empty($_FILES['avatar_file']) && is_uploaded_file($_FILES['avatar_file']['tmp_name'])) {
                    $upload_dir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'avatars';
                    if (!is_dir($upload_dir)) @mkdir($upload_dir, 0755, true);
                    $ext = pathinfo($_FILES['avatar_file']['name'], PATHINFO_EXTENSION);
                    $safe_ext = preg_replace('/[^a-zA-Z0-9]/', '', $ext);
                    // Use timestamp + random suffix to avoid browser cache of same filename
                    $filename = 'avatar_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $new_id) . '_' . time() . '_' . substr(md5(mt_rand()),0,6) . '.' . ($safe_ext ?: 'png');
                    $dest = $upload_dir . DIRECTORY_SEPARATOR . $filename;
                    if (compressAndMoveImage($_FILES['avatar_file']['tmp_name'], $dest, 60, 800, 800)) {
                        $custom_data_array['avatar'] = 'uploads/avatars/' . basename($dest);
                    }
                }

                if (empty($new_id) || empty($new_name)) {
                    $response = ['status' => 'error', 'message' => "សូមបំពេញ អត្តលេខ និង ឈ្មោះ!"];
                } else {
                    $sql_check = "SELECT employee_id FROM users WHERE employee_id = ? AND created_by_admin_id = ?";
                    if ($stmt_check = $mysqli->prepare($sql_check)) {
                        $stmt_check->bind_param("ss", $new_id, $current_admin_id);
                        $stmt_check->execute();
                        $stmt_check->store_result();
                        if ($stmt_check->num_rows > 0) {
                            $response = ['status' => 'error', 'message' => "លេខសម្គាល់បុគ្គលិក ({$new_id}) នេះមានក្នុងប្រព័ន្ធរបស់អ្នករួចហើយ!"];
                        } else {
                            $new_pass_hash = hashPassword(null);
                            // Convert custom data array to JSON
                            // Persist group_id inside custom_data for lightweight relation (no ALTER to users)
                            if ($new_group_id > 0) { $custom_data_array['group_id'] = $new_group_id; }
                            $custom_data_json = json_encode($custom_data_array, JSON_UNESCAPED_UNICODE);

                            $sql = "INSERT INTO users (employee_id, password, name, custom_data, user_role, access_mode, created_by_admin_id) VALUES (?, ?, ?, ?, 'User', 'Free', ?)";

                            if ($stmt = $mysqli->prepare($sql)) {
                                $stmt->bind_param("sssss", $new_id, $new_pass_hash, $new_name, $custom_data_json, $current_admin_id);
                                if ($stmt->execute()) { $response = ['status' => 'success', 'message' => "អ្នកប្រើប្រាស់ថ្មី (User) ត្រូវបានបង្កើត។ (សូមកំណត់ច្បាប់ម៉ោង!)"]; }
                                else { $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការបង្កើត: " . $stmt->error]; }
                                $stmt->close();
                            }
                        }
                        $stmt_check->close();
                    }
                }
                break;

            case 'update_user_info':
                $id = $_POST['edit_id'] ?? '';
                $new_id = trim($_POST['new_id'] ?? $id);
                $name = $_POST['edit_name'] ?? '';
                $edit_group_id = (int)($_POST['edit_group_id'] ?? 0);
                $custom_data_array = $_POST['custom'] ?? [];

                if (empty($id) || empty($name) || empty($new_id)) {
                    $response = ['status' => 'error', 'message' => "ទិន្នន័យមិនពេញលេញសម្រាប់ការកែសម្រួល!"];
                } else {
                    // Check if new_id already exists (if it's different from current id)
                    if ($new_id !== $id) {
                        $check_sql = "SELECT 1 FROM users WHERE employee_id = ? LIMIT 1";
                        if ($stmt_check = $mysqli->prepare($check_sql)) {
                            $stmt_check->bind_param("s", $new_id);
                            $stmt_check->execute();
                            $res_check = $stmt_check->get_result();
                            if ($res_check && $res_check->num_rows > 0) {
                                $response = ['status' => 'error', 'message' => "លេខសម្គាល់បុគ្គលិក ({$new_id}) នេះមានក្នុងប្រព័ន្ធរួចហើយ!"];
                                $stmt_check->close();
                                break;
                            }
                            $stmt_check->close();
                        }
                    }

                    // Load existing custom_data and merge
                    $existing = [];
                    $get_sql = "SELECT custom_data FROM users WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE) LIMIT 1";
                    if ($g = $mysqli->prepare($get_sql)) {
                        $g->bind_param("sii", $id, $current_admin_id, $is_super_admin);
                        $g->execute();
                        $res = $g->get_result();
                        if ($row = $res->fetch_assoc()) {
                            $existing = json_decode($row['custom_data'] ?? '{}', true) ?: [];
                        }
                        $g->close();
                    }

                    // Merge posted custom data over existing
                    $merged = array_merge($existing, $custom_data_array);
                    // Update group assignment if provided
                    if ($edit_group_id > 0) { $merged['group_id'] = $edit_group_id; }

                    // Handle avatar upload if provided
                    if (!empty($_FILES['avatar_file']) && is_uploaded_file($_FILES['avatar_file']['tmp_name'])) {
                        $upload_dir = __DIR__ . DIRECTORY_SEPARATOR . 'uploads' . DIRECTORY_SEPARATOR . 'avatars';
                        if (!is_dir($upload_dir)) @mkdir($upload_dir, 0755, true);
                        $ext = pathinfo($_FILES['avatar_file']['name'], PATHINFO_EXTENSION);
                        $safe_ext = preg_replace('/[^a-zA-Z0-9]/', '', $ext);
                        $old_avatar_path = isset($merged['avatar']) ? $merged['avatar'] : '';
                        $filename = 'avatar_' . preg_replace('/[^a-zA-Z0-9_-]/', '_', $new_id) . '_' . time() . '_' . substr(md5(mt_rand()),0,6) . '.' . ($safe_ext ?: 'png');
                        $dest = $upload_dir . DIRECTORY_SEPARATOR . $filename;
                        if (compressAndMoveImage($_FILES['avatar_file']['tmp_name'], $dest, 60, 800, 800)) {
                            // Remove old avatar if exists and different
                            if (!empty($old_avatar_path)) {
                                $old_fs = __DIR__ . DIRECTORY_SEPARATOR . str_replace(['../','./'], '', $old_avatar_path);
                                if (strpos($old_fs, realpath(__DIR__)) === 0 && @is_file($old_fs)) { @unlink($old_fs); }
                            }
                            $merged['avatar'] = 'uploads/avatars/' . basename($dest);
                        }
                    }

                    $custom_data_json = json_encode($merged, JSON_UNESCAPED_UNICODE);

                    $mysqli->begin_transaction();
                    try {
                        $sql = "UPDATE users SET employee_id = ?, name = ?, custom_data = ? WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
                        if ($stmt = $mysqli->prepare($sql)) {
                            $stmt->bind_param("sssssi", $new_id, $name, $custom_data_json, $id, $current_admin_id, $is_super_admin);
                            if (!$stmt->execute()) {
                                throw new Exception("Update users failed: " . $stmt->error);
                            }
                            $stmt->close();
                        }

                        // If ID changed, update related tables
                        if ($new_id !== $id) {
                            $tables_cols = [
                                'attendance_rules'   => 'employee_id',
                                'user_locations'     => 'employee_id',
                                'checkin_logs'       => 'employee_id',
                                'requests_logs'      => 'employee_id',
                                'active_tokens'      => 'employee_id',
                                'signature_history'  => 'employee_id',
                                'user_access_logs'   => 'employee_id',
                                'user_subaccounts'   => 'parent_employee_id',
                                'auth_tokens'        => 'user_id',
                                'page_access_settings' => 'employee_id',
                                'user_notifications' => 'employee_id'
                            ];
                            foreach ($tables_cols as $table => $col) {
                                // check if table exists before update to be safe
                                $check_table = $mysqli->query("SHOW TABLES LIKE '$table'");
                                if ($check_table && $check_table->num_rows > 0) {
                                    if ($stmt = $mysqli->prepare("UPDATE `$table` SET `$col` = ? WHERE `$col` = ?")) {
                                        $stmt->bind_param("ss", $new_id, $id);
                                        $stmt->execute();
                                        $stmt->close();
                                    }
                                }
                            }

                            // If this user is also an Admin, update references to them in created_by_admin_id/admin_id columns
                            $admin_ref_tables = [
                                'users'              => 'created_by_admin_id',
                                'sidebar_settings'   => 'admin_id',
                                'submenu_settings'   => 'admin_id',
                                'app_settings'       => 'admin_id',
                                'app_scan_settings'  => 'admin_id',
                                'attendance_rules'   => 'created_by_admin_id',
                                'user_locations'     => 'created_by_admin_id',
                                'user_form_fields'   => 'admin_id',
                                'request_form_fields' => 'admin_id',
                                'user_skill_groups'  => 'admin_id',
                                'notifications'      => 'admin_id'
                            ];
                            foreach ($admin_ref_tables as $table => $col) {
                                $check_table = $mysqli->query("SHOW TABLES LIKE '$table'");
                                if ($check_table && $check_table->num_rows > 0) {
                                    if ($stmt = $mysqli->prepare("UPDATE `$table` SET `$col` = ? WHERE `$col` = ?")) {
                                        $stmt->bind_param("ss", $new_id, $id);
                                        $stmt->execute();
                                        $stmt->close();
                                    }
                                }
                            }
                        }

                        $mysqli->commit();
                        $response = ['status' => 'success', 'message' => "ព័ត៌មានបុគ្គលិក {$name} ត្រូវបានកែសម្រួលដោយជោគជ័យ!"];
                    } catch (Exception $e) {
                        $mysqli->rollback();
                        $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការកែសម្រួល: " . $e->getMessage()];
                    }
                }
                break;

            case 'get_user_details': // NEW: សម្រាប់ Edit Modal
                $user_id = $_POST['user_id'] ?? '';
                if(empty($user_id)) {
                    $response = ['status' => 'error', 'message' => 'User ID is required.'];
                    break;
                }

                // Get user's saved data
                $user_sql = "SELECT employee_id, name, custom_data FROM users WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE) LIMIT 1";
                $user_stmt = $mysqli->prepare($user_sql);
                $user_stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin);
                $user_stmt->execute();
                $user_result = $user_stmt->get_result();
                $user_data = $user_result->fetch_assoc();

                if(!$user_data) {
                     $response = ['status' => 'error', 'message' => 'User not found or permission denied.'];
                     break;
                }
                $user_data['custom_data'] = json_decode($user_data['custom_data'] ?? '{}', true);

                // Get all available form fields for this admin
                $fields_sql = "SELECT field_key, field_label, field_type, is_required FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC";
                $fields_stmt = $mysqli->prepare($fields_sql);
                $fields_stmt->bind_param("s", $current_admin_id);
                $fields_stmt->execute();
                $fields_result = $fields_stmt->get_result();
                $form_fields = $fields_result->fetch_all(MYSQLI_ASSOC);

                // Load available groups for this admin
                ensure_user_groups_table($mysqli);
                $grp_stmt = $mysqli->prepare("SELECT id, group_name FROM user_skill_groups WHERE admin_id = ? ORDER BY sort_order ASC, group_name ASC");
                $grp_stmt->bind_param("s", $current_admin_id);
                $grp_stmt->execute();
                $groups_res = $grp_stmt->get_result();
                $groups_list = [];
                while($gr = $groups_res->fetch_assoc()) { $groups_list[] = $gr; }
                $grp_stmt->close();

                $response = [
                    'status' => 'success',
                    'user_data' => $user_data,
                    'form_fields' => $form_fields,
                    'groups' => $groups_list
                ];
                break;

            // (Removed) 'fetch_users_snapshot' auto-refresh endpoint

            case 'duplicate_user': // NEW: Duplicate existing user
                // Permissions: must have create_user access
                if (!hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check)) {
                    $response = ['status' => 'error', 'message' => 'Access denied.'];
                    break;
                }

                $src_id = trim($_POST['src_id'] ?? '');
                $new_id = trim($_POST['new_id'] ?? '');
                $new_name = trim($_POST['new_name'] ?? '');
                $copy_rules = isset($_POST['copy_rules']) ? (int)$_POST['copy_rules'] : 1;
                $copy_locations = isset($_POST['copy_locations']) ? (int)$_POST['copy_locations'] : 1;

                if ($src_id === '' || $new_id === '') {
                    $response = ['status' => 'error', 'message' => 'សូមបំពេញ ID ដើម និង ID ថ្មី!'];
                    break;
                }

                // Ensure source user is in scope and is a normal User
                $src_sql = "SELECT name, custom_data FROM users WHERE employee_id = ? AND user_role = 'User' AND (created_by_admin_id = ? OR ? = TRUE) LIMIT 1";
                if (!($stmt = $mysqli->prepare($src_sql))) { $response = ['status' => 'error', 'message' => 'DB error']; break; }
                $stmt->bind_param("ssi", $src_id, $current_admin_id, $is_super_admin);
                $stmt->execute();
                $src_res = $stmt->get_result();
                $src_user = $src_res->fetch_assoc();
                $stmt->close();
                if (!$src_user) { $response = ['status' => 'error', 'message' => 'មិនរកឃើញអ្នកប្រើប្រាស់ដើម ឬគ្មានសិទ្ធិ។']; break; }

                // Check new ID uniqueness under this admin (consistent with add_user)
                $check_sql = "SELECT employee_id FROM users WHERE employee_id = ? AND created_by_admin_id = ?";
                if ($chk = $mysqli->prepare($check_sql)) {
                    $chk->bind_param("ss", $new_id, $current_admin_id);
                    $chk->execute();
                    $chk->store_result();
                    if ($chk->num_rows > 0) {
                        $chk->close();
                        $response = ['status' => 'error', 'message' => "លេខសម្គាល់បុគ្គលិក ({$new_id}) នេះមានក្នុងប្រព័ន្ធរបស់អ្នករួចហើយ!"];
                        break;
                    }
                    $chk->close();
                }

                $dup_name = $new_name !== '' ? $new_name : ($src_user['name'] . ' (Copy)');
                $custom_json = $src_user['custom_data'] ?? '{}';
                // Ensure valid JSON string
                $custom_json = is_string($custom_json) ? $custom_json : json_encode($custom_json, JSON_UNESCAPED_UNICODE);

                // Create random password for the duplicate
                $new_pass_hash = hashPassword(null);

                $ins_sql = "INSERT INTO users (employee_id, password, name, custom_data, user_role, access_mode, created_by_admin_id) VALUES (?, ?, ?, ?, 'User', 'Free', ?)";
                if ($ins = $mysqli->prepare($ins_sql)) {
                    $ins->bind_param("sssss", $new_id, $new_pass_hash, $dup_name, $custom_json, $current_admin_id);
                    if (!$ins->execute()) {
                        $ins->close();
                        $response = ['status' => 'error', 'message' => 'មានបញ្ហាក្នុងការបង្កើតអ្នកប្រើប្រាស់ថ្មី: ' . $mysqli->error];
                        break;
                    }
                    $ins->close();
                } else {
                    $response = ['status' => 'error', 'message' => 'DB error while inserting user.'];
                    break;
                }

                // Optionally copy time rules
                if ($copy_rules) {
                    $copy_rules_sql = "INSERT INTO attendance_rules (employee_id, type, start_time, end_time, status, created_by_admin_id)
                                       SELECT ?, type, start_time, end_time, status, ?
                                       FROM attendance_rules WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
                    if ($cr = $mysqli->prepare($copy_rules_sql)) {
                        $cr->bind_param("ssssi", $new_id, $current_admin_id, $src_id, $current_admin_id, $is_super_admin);
                        $cr->execute();
                        $cr->close();
                    }
                }

                // Optionally copy location assignments
                if ($copy_locations) {
                    $copy_loc_sql = "INSERT INTO user_locations (employee_id, location_id, custom_radius_meters, created_by_admin_id)
                                     SELECT ?, location_id, custom_radius_meters, ?
                                     FROM user_locations WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
                    if ($cl = $mysqli->prepare($copy_loc_sql)) {
                        $cl->bind_param("ssssi", $new_id, $current_admin_id, $src_id, $current_admin_id, $is_super_admin);
                        $cl->execute();
                        $cl->close();
                    }
                }

                $response = ['status' => 'success', 'message' => "បានចម្លងអ្នកប្រើប្រាស់ទៅជា {$dup_name} ({$new_id}) ដោយជោគជ័យ!"];
                break;

            case 'delete_user': // NEW: Delete a single user
                if (!(hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check) || hasPageAccess($mysqli, 'users', 'list_users', $admin_id_check))) { $response = ['status' => 'error', 'message' => 'Access denied.']; break; }
                $user_id = trim($_POST['user_id'] ?? '');
                if ($user_id === '') { $response = ['status' => 'error', 'message' => 'គ្មាន User ID']; break; }
                // Ensure target is a normal User in scope
                $chk_sql = "SELECT employee_id FROM users WHERE employee_id = ? AND user_role = 'User' AND (created_by_admin_id = ? OR ? = TRUE) LIMIT 1";
                if ($ch = $mysqli->prepare($chk_sql)) {
                    $ch->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin);
                    $ch->execute(); $r = $ch->get_result(); $ok = $r->num_rows > 0; $ch->close();
                    if (!$ok) { $response = ['status' => 'error', 'message' => 'មិនមានសិទ្ធិ ឬមិនមាន User នេះ']; break; }
                }
                // Cleanup dependents
                if ($stmt = $mysqli->prepare("DELETE FROM user_locations WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)")) { $stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                if ($stmt = $mysqli->prepare("DELETE FROM attendance_rules WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)")) { $stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                if ($stmt = $mysqli->prepare("DELETE FROM active_tokens WHERE employee_id = ?")) { $stmt->bind_param("s", $user_id); $stmt->execute(); $stmt->close(); }
                // Delete signature history (scoped by ownership)
                $del_sig_sql = "DELETE sh FROM signature_history sh JOIN users u ON sh.employee_id = u.employee_id WHERE sh.employee_id = ? AND (u.created_by_admin_id = ? OR ? = TRUE)";
                if ($stmt = $mysqli->prepare($del_sig_sql)) { $stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                // Delete check-in logs (scoped by ownership)
                $del_ci_sql = "DELETE cl FROM checkin_logs cl JOIN users u ON cl.employee_id = u.employee_id WHERE cl.employee_id = ? AND (u.created_by_admin_id = ? OR ? = TRUE)";
                if ($stmt = $mysqli->prepare($del_ci_sql)) { $stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                // Delete request logs (scoped by ownership)
                $del_req_sql = "DELETE rl FROM requests_logs rl JOIN users u ON rl.employee_id = u.employee_id WHERE rl.employee_id = ? AND (u.created_by_admin_id = ? OR ? = TRUE)";
                if ($stmt = $mysqli->prepare($del_req_sql)) { $stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                // Finally delete user
                if ($stmt = $mysqli->prepare("DELETE FROM users WHERE employee_id = ? AND user_role = 'User' AND (created_by_admin_id = ? OR ? = TRUE)")) {
                    $stmt->bind_param("ssi", $user_id, $current_admin_id, $is_super_admin);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => 'បានលុប User ដោយជោគជ័យ'];
                        // Log deletion event
                        if ($log = $mysqli->prepare("INSERT INTO user_access_logs (employee_id, event_type, ip_address, user_agent) VALUES (?, 'delete_user', ?, ?)")) {
                            $ip = $_SERVER['REMOTE_ADDR'] ?? ''; $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                            $log->bind_param("sss", $user_id, $ip, $ua); $log->execute(); $log->close();
                        }
                    } else { $response = ['status' => 'error', 'message' => 'លុបបរាជ័យ: ' . $stmt->error]; }
                    $stmt->close();
                } else { $response = ['status' => 'error', 'message' => 'DB error']; }
                break;

            case 'bulk_delete_users': // NEW: Bulk delete selected users
                if (!(hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check) || hasPageAccess($mysqli, 'users', 'list_users', $admin_id_check))) { $response = ['status' => 'error', 'message' => 'Access denied.']; break; }
                $ids = $_POST['employee_ids'] ?? [];
                if (!is_array($ids) || count($ids) === 0) { $response = ['status' => 'error', 'message' => 'មិនបានជ្រើសរើស User ទេ']; break; }
                $deleted = 0; $failed = 0;
                foreach ($ids as $uid) {
                    $uid = trim($uid);
                    if ($uid === '') { $failed++; continue; }
                    // Scope + type check
                    $ok = false;
                    if ($ch = $mysqli->prepare("SELECT employee_id FROM users WHERE employee_id = ? AND user_role = 'User' AND (created_by_admin_id = ? OR ? = TRUE) LIMIT 1")) {
                        $ch->bind_param("ssi", $uid, $current_admin_id, $is_super_admin); $ch->execute(); $rr = $ch->get_result(); $ok = $rr->num_rows > 0; $ch->close();
                    }
                    if (!$ok) { $failed++; continue; }
                    // Delete dependents
                    if ($stmt = $mysqli->prepare("DELETE FROM user_locations WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)")) { $stmt->bind_param("ssi", $uid, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                    if ($stmt = $mysqli->prepare("DELETE FROM attendance_rules WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)")) { $stmt->bind_param("ssi", $uid, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                    if ($stmt = $mysqli->prepare("DELETE FROM active_tokens WHERE employee_id = ?")) { $stmt->bind_param("s", $uid); $stmt->execute(); $stmt->close(); }
                    // Delete signature history (scoped by ownership)
                    $del_sig_sql = "DELETE sh FROM signature_history sh JOIN users u ON sh.employee_id = u.employee_id WHERE sh.employee_id = ? AND (u.created_by_admin_id = ? OR ? = TRUE)";
                    if ($stmt = $mysqli->prepare($del_sig_sql)) { $stmt->bind_param("ssi", $uid, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                    // Delete logs under scope
                    $del_ci_sql = "DELETE cl FROM checkin_logs cl JOIN users u ON cl.employee_id = u.employee_id WHERE cl.employee_id = ? AND (u.created_by_admin_id = ? OR ? = TRUE)";
                    if ($stmt = $mysqli->prepare($del_ci_sql)) { $stmt->bind_param("ssi", $uid, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                    $del_req_sql = "DELETE rl FROM requests_logs rl JOIN users u ON rl.employee_id = u.employee_id WHERE rl.employee_id = ? AND (u.created_by_admin_id = ? OR ? = TRUE)";
                    if ($stmt = $mysqli->prepare($del_req_sql)) { $stmt->bind_param("ssi", $uid, $current_admin_id, $is_super_admin); $stmt->execute(); $stmt->close(); }
                    if ($stmt = $mysqli->prepare("DELETE FROM users WHERE employee_id = ? AND user_role = 'User' AND (created_by_admin_id = ? OR ? = TRUE)")) {
                        $stmt->bind_param("ssi", $uid, $current_admin_id, $is_super_admin);
                        if ($stmt->execute()) {
                            $deleted++;
                            // Log each successful bulk deletion
                            if ($log = $mysqli->prepare("INSERT INTO user_access_logs (employee_id, event_type, ip_address, user_agent) VALUES (?, 'bulk_delete_user', ?, ?)")) {
                                $ip = $_SERVER['REMOTE_ADDR'] ?? ''; $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
                                $log->bind_param("sss", $uid, $ip, $ua); $log->execute(); $log->close();
                            }
                        } else { $failed++; }
                        $stmt->close();
                    } else { $failed++; }
                }
                $msg = "លុបបាន {$deleted} និងបរាជ័យ {$failed}";
                $response = ['status' => ($deleted > 0 ? 'success' : 'error'), 'message' => $msg];
                break;

            // ===== User Skill Groups (Categories) =====
            case 'add_user_group':
                if (!canManageUserGroups($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                ensure_user_groups_table($mysqli);
                $group_name = trim($_POST['group_name'] ?? '');
                if ($group_name === '') { $response = ['status'=>'error','message'=>'សូមបំពេញឈ្មោះក្រុម']; break; }
                // Determine next sort_order
                $next_order = 0;
                if ($res = $mysqli->prepare("SELECT COALESCE(MAX(sort_order),0)+1 AS next_order FROM user_skill_groups WHERE admin_id = ?")) {
                    $res->bind_param("s", $current_admin_id); $res->execute(); $r = $res->get_result()->fetch_assoc(); $next_order = (int)($r['next_order'] ?? 1); $res->close();
                }
                $stmt = $mysqli->prepare("INSERT INTO user_skill_groups (admin_id, group_name, sort_order) VALUES (?, ?, ?)");
                $stmt->bind_param("ssi", $current_admin_id, $group_name, $next_order);
                if ($stmt->execute()) { $response=['status'=>'success','message'=>'បានបង្កើតក្រុមថ្មី','group_id'=>$stmt->insert_id]; }
                else { $response=['status'=>'error','message'=>'DB error: '.$stmt->error]; }
                $stmt->close();
                break;

            case 'rename_user_group':
                if (!canManageUserGroups($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                ensure_user_groups_table($mysqli);
                $gid = (int)($_POST['group_id'] ?? 0);
                $new_name = trim($_POST['group_name'] ?? '');
                if ($gid <= 0 || $new_name==='') { $response=['status'=>'error','message'=>'ទិន្នន័យមិនពេញលេញ']; break; }
                $stmt = $mysqli->prepare("UPDATE user_skill_groups SET group_name = ? WHERE id = ? AND admin_id = ?");
                $stmt->bind_param("sis", $new_name, $gid, $current_admin_id);
                if ($stmt->execute()) { $response=['status'=>'success','message'=>'បានកែឈ្មោះក្រុម']; } else { $response=['status'=>'error','message'=>'DB error: '.$stmt->error]; }
                $stmt->close();
                break;

            case 'reorder_user_groups':
                if (!canManageUserGroups($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                ensure_user_groups_table($mysqli);
                $ordered = $_POST['ordered_group_ids'] ?? [];
                if (!is_array($ordered) || count($ordered) === 0) { $response = ['status'=>'error','message'=>'No group order received']; break; }
                // Keep only positive integers
                $ids = array_values(array_filter(array_map('intval', $ordered), function($v){ return $v > 0; }));
                if (count($ids) === 0) { $response = ['status'=>'error','message'=>'No valid group IDs']; break; }
                $mysqli->begin_transaction();
                try {
                    $pos = 10;
                    if ($upd = $mysqli->prepare("UPDATE user_skill_groups SET sort_order = ? WHERE id = ? AND admin_id = ?")) {
                        foreach ($ids as $gid) {
                            $upd->bind_param('iis', $pos, $gid, $current_admin_id);
                            $upd->execute();
                            $pos += 10;
                        }
                        $upd->close();
                    }
                    $mysqli->commit();
                    $response = ['status' => 'success', 'message' => 'បានរក្សាទុកលំដាប់ក្រុម'];
                } catch (Exception $e) {
                    $mysqli->rollback();
                    $response = ['status' => 'error', 'message' => 'DB error: '.$e->getMessage()];
                }
                break;

            case 'delete_user_group':
                if (!canManageUserGroups($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                ensure_user_groups_table($mysqli);
                $gid = (int)($_POST['group_id'] ?? 0);
                if ($gid <= 0) { $response=['status'=>'error','message'=>'Group ID invalid']; break; }
                // Delete the group (scoped to admin)
                $stmt = $mysqli->prepare("DELETE FROM user_skill_groups WHERE id = ? AND admin_id = ?");
                $stmt->bind_param("is", $gid, $current_admin_id);
                $ok = $stmt->execute(); $err = $stmt->error; $stmt->close();
                if (!$ok) { $response=['status'=>'error','message'=>'DB error: '.$err]; break; }
                // Also remove group_id from users.custom_data for this admin
                $sel = $mysqli->prepare("SELECT employee_id, custom_data FROM users WHERE created_by_admin_id = ?");
                $sel->bind_param("s", $current_admin_id); $sel->execute(); $res = $sel->get_result();
                while($u = $res->fetch_assoc()){
                    $cd = json_decode($u['custom_data'] ?? '{}', true) ?: [];
                    if (isset($cd['group_id']) && (int)$cd['group_id'] === $gid) {
                        unset($cd['group_id']);
                        $json = json_encode($cd, JSON_UNESCAPED_UNICODE);
                        if ($up = $mysqli->prepare("UPDATE users SET custom_data = ? WHERE employee_id = ? AND created_by_admin_id = ?")) {
                            $up->bind_param("sss", $json, $u['employee_id'], $current_admin_id); $up->execute(); $up->close();
                        }
                    }
                }
                $sel->close();
                $response=['status'=>'success','message'=>'បានលុបក្រុម និងដកចេញពីអ្នកប្រើប្រាស់ដែលបានកំណត់'];
                break;

            case 'assign_user_group':
                // Permission: need user management capabilities or categories access
                if (!canManageUserGroups($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                // Assign or clear group for one or many users (normal admins can only their users)
                $group_id = (int)($_POST['group_id'] ?? 0); // 0 means clear
                $ids = $_POST['employee_ids'] ?? [];
                if (!is_array($ids)) { $ids = [$ids]; }
                $updated = 0; $failed = 0;
                foreach ($ids as $uid) {
                    $uid = trim($uid);
                    if ($uid==='') { $failed++; continue; }
                    // Scope check
                    $ok = false;
                    if ($is_super_admin) {
                        // Allow only if this user belongs to current admin or self; to keep safe, require ownership unless super admin wants to bypass (skip for now)
                        $own_sql = "SELECT created_by_admin_id FROM users WHERE employee_id = ?";
                        if ($ch = $mysqli->prepare($own_sql)) { $ch->bind_param("s", $uid); $ch->execute(); $r=$ch->get_result(); $row=$r->fetch_assoc(); $ch->close(); $ok = (bool)$row; $owner_id = $row['created_by_admin_id'] ?? $current_admin_id; }
                    } else {
                        $own_sql = "SELECT 1 FROM users WHERE employee_id = ? AND created_by_admin_id = ? LIMIT 1";
                        if ($ch = $mysqli->prepare($own_sql)) { $ch->bind_param("ss", $uid, $current_admin_id); $ch->execute(); $r=$ch->get_result(); $ok=$r && $r->num_rows>0; $ch->close(); }
                        $owner_id = $current_admin_id;
                    }
                    if (!$ok) { $failed++; continue; }
                    // Get current custom_data
                    $g = $mysqli->prepare("SELECT custom_data FROM users WHERE employee_id = ? LIMIT 1");
                    $g->bind_param("s", $uid); $g->execute(); $rr = $g->get_result(); $row = $rr->fetch_assoc(); $g->close();
                    $cd = json_decode($row['custom_data'] ?? '{}', true) ?: [];
                    if ($group_id > 0) { $cd['group_id'] = $group_id; } else { unset($cd['group_id']); }
                    $json = json_encode($cd, JSON_UNESCAPED_UNICODE);
                    $u = $mysqli->prepare("UPDATE users SET custom_data = ? WHERE employee_id = ?");
                    $u->bind_param("ss", $json, $uid);
                    if ($u->execute()) { $updated++; } else { $failed++; }
                    $u->close();
                }
                $response = ['status' => ($updated>0?'success':'error'), 'message' => "បានកំណត់ក្រុម {$updated} នាក់; បរាជ័យ {$failed}"];
                break;

            case 'bulk_delete_logs':
                // Permanently delete multiple checkin_logs by PK (scoped to admin unless super admin)
                $raw_ids = $_POST['log_ids'] ?? [];
                if (!is_array($raw_ids)) {
                    // jQuery may send as log_ids[] or as JSON string
                    if (is_string($raw_ids)) {
                        $decoded = json_decode($raw_ids, true);
                        $raw_ids = is_array($decoded) ? $decoded : [];
                    } else {
                        $raw_ids = [];
                    }
                }
                $ids = array_values(array_filter(array_map('intval', $raw_ids)));
                if (count($ids) === 0) { $response = ['status' => 'error', 'message' => 'មិនបានជ្រើសរើសតារាងដែលត្រូវលុបទេ (No IDs).']; break; }

                // Detect primary key column for checkin_logs safely
                $pk = 'id';
                $cols = $mysqli->query("SHOW COLUMNS FROM `checkin_logs`");
                if ($cols) {
                    while ($c = $cols->fetch_assoc()) {
                        if (!empty($c['Key']) && strtoupper($c['Key']) === 'PRI') { $pk = $c['Field']; break; }
                    }
                    $cols->close();
                }

                // Build safe integer list for IN() clause
                $id_list = implode(',', array_map('intval', $ids));

                // First, find which IDs actually exist and are in-scope for this admin
                if ($is_super_admin) {
                    $select_sql = "SELECT `{$pk}` as pk FROM `checkin_logs` WHERE `{$pk}` IN ({$id_list})";
                } else {
                    $safe_admin = $mysqli->real_escape_string($current_admin_id);
                    $select_sql = "SELECT cl.`{$pk}` as pk FROM `checkin_logs` cl JOIN users u ON cl.employee_id = u.employee_id WHERE u.created_by_admin_id = '{$safe_admin}' AND cl.`{$pk}` IN ({$id_list})";
                }

                $found = [];
                if ($res = $mysqli->query($select_sql)) {
                    while ($r = $res->fetch_assoc()) { $found[] = (int)$r['pk']; }
                    $res->close();
                }

                if (count($found) === 0) { $response = ['status' => 'error', 'message' => 'មិនមានតារាងណាដែលអាចលុបបាន ឬគ្មានសិទ្ធិ។']; break; }

                $found_list = implode(',', $found);
                if ($is_super_admin) {
                    $del_sql = "DELETE FROM `checkin_logs` WHERE `{$pk}` IN ({$found_list})";
                } else {
                    $safe_admin = $mysqli->real_escape_string($current_admin_id);
                    $del_sql = "DELETE cl FROM `checkin_logs` cl JOIN users u ON cl.employee_id = u.employee_id WHERE u.created_by_admin_id = '{$safe_admin}' AND cl.`{$pk}` IN ({$found_list})";
                }

                if ($mysqli->query($del_sql)) {
                    $deleted_count = $mysqli->affected_rows;
                    $response = ['status' => 'success', 'message' => "បានលុប {$deleted_count} សំណុទ្ធ (deleted records)", 'deleted_ids' => $found, 'requested_ids' => $ids];
                } else {
                    $response = ['status' => 'error', 'message' => 'DB delete failed: ' . $mysqli->error];
                }
                break;

			case 'add_admin':
				if (!$can_manage_admin) {
					$response = ['status' => 'error', 'message' => "អ្នកមិនមែនជា Super Admin! មិនមានសិទ្ធិចូលប្រើមុខងារនេះទេ។"];
					break;
				}

				$admin_id = trim($_POST['admin_id'] ?? '');
				$admin_pass_plain = $_POST['admin_password'] ?? '';
				$admin_name = trim($_POST['admin_name'] ?? '');
				$admin_role = 'Admin';

				if (empty($admin_id) || empty($admin_pass_plain) || empty($admin_name)) {
					$response = ['status' => 'error', 'message' => "សូមបំពេញ Admin ID, ឈ្មោះ និង ពាក្យសម្ងាត់!"];
				} else {
					$sql_check = "SELECT employee_id FROM users WHERE employee_id = ?";
					if ($stmt_check = $mysqli->prepare($sql_check)) {
						$stmt_check->bind_param("s", $admin_id);
						$stmt_check->execute();
						$stmt_check->store_result();
						if ($stmt_check->num_rows > 0) {
							$response = ['status' => 'error', 'message' => "Admin ID ({$admin_id}) នេះមានក្នុងប្រព័ន្ធរួចហើយ!"];
						} else {
							$admin_pass = hashPassword($admin_pass_plain);
							$sql = "INSERT INTO users (employee_id, password, name, user_role, access_mode, is_super_admin, created_by_admin_id) VALUES (?, ?, ?, ?, 'Free', FALSE, ?)";
							if ($stmt = $mysqli->prepare($sql)) {
								$stmt->bind_param("sssss", $admin_id, $admin_pass, $admin_name, $admin_role, $current_admin_id);
								if ($stmt->execute()) {
                                    initialize_sidebar_settings($mysqli, $admin_id);
                                    initialize_default_user_fields($mysqli, $admin_id); // NEW
									$response = ['status' => 'success', 'message' => "គណនី Admin ថ្មីត្រូវបានបង្កើតដោយជោគជ័យ!"];
								} else {
									$response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការបង្កើត Admin: " . $stmt->error];
								}
								$stmt->close();
							} else {
								$response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការត្រៀម Query: " . $mysqli->error];
							}
						}
						$stmt_check->close();
					}
				}
				break;

            // START: AJAX Handlers ថ្មីสำหรับ Request Fields
            case 'add_request_field':
                if (!hasPageAccess($mysqli, 'settings', 'manage_request_fields', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied.'];
                    break;
                }
                $label = trim($_POST['field_label'] ?? '');
                $request_type = $_POST['request_type'] ?? 'All';
                $field_type = $_POST['field_type'] ?? 'text';
                $is_required = isset($_POST['is_required']) ? 1 : 0;

                if (empty($label) || empty($request_type)) {
                    $response = ['status' => 'error', 'message' => 'សូមបំពេញ Label និងជ្រើសរើសប្រភេទសំណើរ។'];
                    break;
                }

                $key = 'custom_' . strtolower(preg_replace('/[^a-zA-Z0-9]/', '_', $label)) . '_' . uniqid();

                $sql = "INSERT INTO request_form_fields (admin_id, request_type, field_key, field_label, field_type, is_required) VALUES (?, ?, ?, ?, ?, ?)";
                if($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("sssssi", $current_admin_id, $request_type, $key, $label, $field_type, $is_required);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "Field '{$label}' ត្រូវបានបង្កើតសម្រាប់ '{$request_type}' ដោយជោគជ័យ។"];
                    } else {
                        $response = ['status' => 'error', 'message' => 'មានកំហុសក្នុងការបង្កើត Field (Key อาจซ้ำกัน): ' . $stmt->error];
                    }
                    $stmt->close();
                }
                break;

            case 'delete_request_field':
                if (!hasPageAccess($mysqli, 'settings', 'manage_request_fields', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied.'];
                    break;
                }
                $field_id = (int)($_POST['field_id'] ?? 0);
                if(empty($field_id)) {
                    $response = ['status' => 'error', 'message' => 'Invalid Field ID.'];
                    break;
                }
                $sql = "DELETE FROM request_form_fields WHERE id = ? AND admin_id = ? AND is_deletable = 1";
                if($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("is", $field_id, $current_admin_id);
                    if($stmt->execute() && $stmt->affected_rows > 0) {
                        $response = ['status' => 'success', 'message' => 'Field សំណើរត្រូវបានលុបដោយជោគជ័យ។'];
                    } else {
                         $response = ['status' => 'error', 'message' => 'មិនអាចលុប Field បានទេ ឬអ្នកមិនមានសិទ្ធិ។'];
                    }
                    $stmt->close();
                }
                break;

            case 'toggle_request_field_status':
                if (!hasPageAccess($mysqli, 'settings', 'manage_request_fields', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied.'];
                    break;
                }
                $field_id = (int)($_POST['field_id'] ?? 0);
                $new_status = (int)($_POST['is_active'] ?? 0);

                if (empty($field_id)) {
                    $response = ['status' => 'error', 'message' => 'Invalid Field ID.'];
                    break;
                }

                $sql = "UPDATE request_form_fields SET is_active = ? WHERE id = ? AND admin_id = ?";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("iis", $new_status, $field_id, $current_admin_id);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "สถานะของ Field ត្រូវបានផ្លាស់ប្តូរដោយជោគជ័យ។"];
                    } else {
                        $response = ['status' => 'error', 'message' => 'មានកំហុសក្នុងការអัปដេតสถานะ: ' . $stmt->error];
                    }
                    $stmt->close();
                } else {
                    $response = ['status' => 'error', 'message' => 'Database prepare error: ' . $mysqli->error];
                }
                break;
            // END: AJAX Handlers ថ្មី

         // NEW: Thêm AJAX cases สำหรับจัดการ fields
            case 'add_user_field':
                $label = trim($_POST['field_label'] ?? '');

                if (empty($label)) {
                    $response = ['status' => 'error', 'message' => 'ឈ្មោះ Field (Label) មិនអាចទទេបានទេ។'];
                    break;
                }

                // --- START: កូដដែលបានកែសម្រួល (មិនណែនាំឱ្យប្រើ) ---
                // Key គឺ Label ដូចគ្នាเลย โดยแค่แทนที่ដកឃ្លាด้วย underscore
                // WARNING: This can cause database and encoding issues.
                $key = str_replace(' ', '_', $label);
                // --- END: កូដដែលបានកែសម្រួល ---

                $type = $_POST['field_type'] ?? 'text';
                $is_required = isset($_POST['is_required']) ? 1 : 0;

                $sql = "INSERT INTO user_form_fields (admin_id, field_key, field_label, field_type, is_required) VALUES (?, ?, ?, ?, ?)";
                if($stmt = $mysqli->prepare($sql)) {
                    // ត្រូវប្រាកដថា Connection របស់អ្នកគឺ utf8mb4
                    $stmt->bind_param("ssssi", $current_admin_id, $key, $label, $type, $is_required);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "Field '{$label}' ត្រូវបានបង្កើតដោយជោគជ័យ។"];
                    } else {
                        $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការបង្កើត Field (Key '{$key}' អាចមានរួចហើយ): " . $stmt->error];
                    }
                    $stmt->close();
                }
                break;

            case 'delete_user_field':
                $field_id = (int)($_POST['field_id'] ?? 0);
                if(empty($field_id)) {
                    $response = ['status' => 'error', 'message' => 'Invalid Field ID.'];
                    break;
                }
                // is_deletable=1 check is important to prevent deleting default fields if needed
                $sql = "DELETE FROM user_form_fields WHERE id = ? AND admin_id = ? AND is_deletable = 1";
                if($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("is", $field_id, $current_admin_id);
                    if($stmt->execute() && $stmt->affected_rows > 0) {
                        $response = ['status' => 'success', 'message' => 'Field ត្រូវបានលុបដោយជោគជ័យ។'];
                    } else {
                         $response = ['status' => 'error', 'message' => 'មិនអាចលុប Field បានទេ ឬអ្នកមិនមានសិទ្ធិ។'];
                    }
                    $stmt->close();
                }
                break;

            case 'reorder_user_fields':
                // Expecting ordered_field_ids as array of IDs in new order
                $ordered = $_POST['ordered_field_ids'] ?? [];
                if (!is_array($ordered) || count($ordered) === 0) {
                    $response = ['status' => 'error', 'message' => 'No ordering provided.'];
                    break;
                }
                $mysqli->begin_transaction();
                try {
                    $pos = 10;
                    $upd = $mysqli->prepare("UPDATE user_form_fields SET field_order = ? WHERE id = ? AND admin_id = ?");
                    foreach ($ordered as $fid) {
                        $fid = (int)$fid;
                        $upd->bind_param('iis', $pos, $fid, $current_admin_id);
                        $upd->execute();
                        $pos += 10;
                    }
                    $upd->close();
                    $mysqli->commit();
                    $response = ['status' => 'success', 'message' => 'Field order updated.'];
                } catch (Exception $e) {
                    $mysqli->rollback();
                    $response = ['status' => 'error', 'message' => 'DB error: ' . $e->getMessage()];
                }
                break;

            case 'update_user_field':
                $fid = (int)($_POST['field_id'] ?? 0);
                $label = trim($_POST['field_label'] ?? '');
                $is_required = isset($_POST['is_required']) ? 1 : 0;
                if (empty($fid) || $label === '') {
                    $response = ['status' => 'error', 'message' => 'Invalid parameters.'];
                    break;
                }
                $sql = "UPDATE user_form_fields SET field_label = ?, is_required = ? WHERE id = ? AND admin_id = ?";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("siis", $label, $is_required, $fid, $current_admin_id);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => 'Field updated.'];
                    } else {
                        $response = ['status' => 'error', 'message' => 'Update failed: ' . $stmt->error];
                    }
                    $stmt->close();
                } else {
                    $response = ['status' => 'error', 'message' => 'DB prepare error: ' . $mysqli->error];
                }
                break;

            case 'update_request_status':
                $request_id = (int)($_POST['request_id'] ?? 0);
                $new_status = $_POST['new_status'] ?? '';

                if (empty($request_id) || !in_array($new_status, ['Approved', 'Rejected'])) {
                    $response = ['status' => 'error', 'message' => 'Invalid data provided for status update.'];
                    break;
                }

                $check_permission_sql = "
                    SELECT rl.id
                    FROM requests_logs rl
                    JOIN users u ON rl.employee_id = u.employee_id
                    WHERE rl.id = ?
                ";
                $params = [$request_id];
                $types = "i";

                if (!$is_super_admin) {
                    $check_permission_sql .= " AND u.created_by_admin_id = ?";
                    $params[] = $current_admin_id;
                    $types .= "s";
                }

                $stmt_check = $mysqli->prepare($check_permission_sql);
                $stmt_check->bind_param($types, ...$params);
                $stmt_check->execute();
                $result_check = $stmt_check->get_result();

                if ($result_check->num_rows === 0) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied. You cannot manage this request.'];
                    $stmt_check->close();
                    break;
                }
                $stmt_check->close();

                $update_sql = "UPDATE requests_logs SET request_status = ? WHERE id = ?";
                if ($stmt_update = $mysqli->prepare($update_sql)) {
                    $stmt_update->bind_param("si", $new_status, $request_id); //កែប្រែទីតាំងអថេរ

                    if ($stmt_update->execute()) {
                        $action_text = ($new_status == 'Approved') ? 'approved' : 'rejected';
                        $response = ['status' => 'success', 'message' => "Request #{$request_id} has been successfully {$action_text}."];
                    } else {
                        $response = ['status' => 'error', 'message' => 'Database error during status update: ' . $stmt_update->error];
                    }
                    $stmt_update->close();
                } else {
                    $response = ['status' => 'error', 'message' => 'Database prepare error: ' . $mysqli->error];
                }
                break;

			case 'save_time_rules':
                // Permission check: broader implicit permission via canManageTimeRules
                if (!canManageTimeRules($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                $employee_id = $_POST['rule_employee_id'] ?? '';
				$rules_json = $_POST['rules_json'] ?? '[]';
				$rules = json_decode($rules_json, true);

				if (empty($employee_id)) {
					$response = ['status' => 'error', 'message' => "មិនមាន ID បុគ្គលិកទេ។"];
					break;
				}

				$sql_delete = "DELETE FROM attendance_rules WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
				if ($stmt_delete = $mysqli->prepare($sql_delete)) {
					$stmt_delete->bind_param("ssi", $employee_id, $current_admin_id, $is_super_admin);
					$stmt_delete->execute();
					$stmt_delete->close();
				}

				$has_error = false;

				if (!empty($rules)) {
					$sql_insert = "INSERT INTO attendance_rules (employee_id, type, start_time, end_time, status, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)";

					if ($stmt = $mysqli->prepare($sql_insert)) {
						foreach ($rules as $rule) {
							$type = $rule['type'] ?? '';
							$start = $rule['start'] ?? '';
							$end = $rule['end'] ?? '';
							$status = $rule['status'] ?? 'Good';

							if (!empty($start) && !empty($end) && !empty($type)) {
								$stmt->bind_param("ssssss", $employee_id, $type, $start, $end, $status, $current_admin_id);
								if (!$stmt->execute()) {
									$response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការបញ្ចូលច្បាប់ម៉ោង: " . $stmt->error];
									$has_error = true;
									break;
								}
							}
						}
						$stmt->close();
					}
				}

				if (!$has_error) {
					$response = ['status' => 'success', 'message' => "ច្បាប់ម៉ោងសម្រាប់បុគ្គលិក {$employee_id} ត្រូវបានរក្សាទុកដោយជោគជ័យ។", 'refresh_url' => "admin_attendance.php?page=users&action=edit_rules&id={$employee_id}"];
				}
				break;

            case 'get_time_rules':
                // Return attendance rules for a given user (AJAX helper for Copy feature)
                if (!canManageTimeRules($mysqli, $admin_id_check)) { $response = ['status'=>'error','message'=>'Access denied']; break; }
                $src_user = $_POST['user_id'] ?? ($_GET['user_id'] ?? '');
                if (empty($src_user)) { $response = ['status'=>'error','message'=>'User ID required']; break; }
                $rules_sql = "SELECT type, start_time, end_time, status FROM attendance_rules WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE) ORDER BY type DESC, start_time ASC";
                if ($stmt = $mysqli->prepare($rules_sql)) {
                    $stmt->bind_param('ssi', $src_user, $current_admin_id, $is_super_admin);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    $rules = [];
                    while ($r = $res->fetch_assoc()) { $rules[] = $r; }
                    $stmt->close();
                    $response = ['status'=>'success','rules'=>$rules];
                } else {
                    $response = ['status'=>'error','message'=>'DB error'];
                }
                break;

			case 'set_global_max_tokens':
				$new_max_tokens = (int)($_POST['global_max_tokens'] ?? 1);

				if ($new_max_tokens < 1 || $new_max_tokens > 10) {
					$response = ['status' => 'error', 'message' => "ចំនួន Token ត្រូវតែចន្លោះពី 1 ដល់ 10!"];
					break;
				}

				$sql = "UPDATE users SET global_max_tokens = ? WHERE employee_id = ?";
				if ($stmt = $mysqli->prepare($sql)) {
					$stmt->bind_param("is", $new_max_tokens, $current_admin_id);
					if ($stmt->execute()) {
						$response = ['status' => 'success', 'message' => "ការកំណត់ Max Tokens របស់អ្នកត្រូវបានរក្សាទុកដោយជោគជ័យ! (តម្លៃថ្មី: {$new_max_tokens})"];
					} else {
						$response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការរក្សាទុក: " . $stmt->error];
					}
					$stmt->close();
				} else {
					$response = ['status' => 'error', 'message' => "Database error: " . $mysqli->error];
				}
				break;

            case 'add_location':
                $loc_name = trim($_POST['location_name'] ?? '');
                $lat = isset($_POST['latitude']) ? (float)$_POST['latitude'] : null;
                $lon = isset($_POST['longitude']) ? (float)$_POST['longitude'] : null;
                $radius = (int)($_POST['radius_meters'] ?? 100);
                $qr_secret = hash('sha256', uniqid(mt_rand(), true));

                // Validate inputs (allow 0.0 values for lat/lon)
                if ($loc_name === '' || $lat === null || $lon === null || !is_numeric($_POST['latitude'] ?? null) || !is_numeric($_POST['longitude'] ?? null)) {
                    $response = ['status' => 'error', 'message' => "សូមបំពេញ ឈ្មោះទីតាំង, Latitude និង Longitude ត្រឹមត្រូវ!"];
                    break;
                }

                // Always insert a new location (allow duplicate names). Requires DB to NOT have a UNIQUE on location_name.
                $sql = "INSERT INTO locations (location_name, latitude, longitude, radius_meters, qr_secret, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("sddiss", $loc_name, $lat, $lon, $radius, $qr_secret, $current_admin_id);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "ទីតាំងថ្មី <strong>{$loc_name}</strong> ត្រូវបានបង្កើតដោយជោគជ័យ។"];
                    } else {
                        if ($stmt->errno == 1062) {
                            $response = ['status' => 'error', 'message' => "Database កំពុងមាន UNIQUE លើឈ្មោះទីតាំង (location_name) — នេះបណ្តាលឲ្យកំហុស Duplicate Entry។ សូមរត់ SQL នៅ 'db/allow_duplicate_location_names.sql' ដើម្បីដក UNIQUE (ឬ ប្តូរទៅ composite unique per admin) ហើយសាកល្បងបន្ថែមម្ដងទៀត។"];
                        } else {
                            $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការបង្កើតទីតាំង: " . $stmt->error];
                        }
                    }
                    $stmt->close();
                }
                break;

            case 'update_location':
                $loc_id_raw = $_POST['edit_loc_id'] ?? '';
                $loc_id = is_numeric($loc_id_raw) ? (int)$loc_id_raw : 0;
                $loc_name = trim($_POST['edit_loc_name'] ?? '');
                $lat = isset($_POST['edit_latitude']) ? (float)$_POST['edit_latitude'] : null;
                $lon = isset($_POST['edit_longitude']) ? (float)$_POST['edit_longitude'] : null;
                $radius = (int)($_POST['edit_radius_meters'] ?? 100);

                // Validate inputs (allow 0.0 for lat/lon, ensure numeric fields provided)
                if ($loc_id <= 0 || $loc_name === '' || !is_numeric($_POST['edit_latitude'] ?? null) || !is_numeric($_POST['edit_longitude'] ?? null)) {
                    $response = ['status' => 'error', 'message' => "ទិន្នន័យទីតាំងមិនពេញលេញសម្រាប់ការកែសម្រួល! សូមបំពេញឈ្មោះ និង Lat/Lon ត្រឹមត្រូវ។"];
                    break;
                }

                $sql = "UPDATE locations SET location_name = ?, latitude = ?, longitude = ?, radius_meters = ? WHERE id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("sddiisi", $loc_name, $lat, $lon, $radius, $loc_id, $current_admin_id, $is_super_admin);
                    if ($stmt->execute()) {
                        $response = ['status' => 'success', 'message' => "ទីតាំង <strong>{$loc_name}</strong> ត្រូវបានកែសម្រួលដោយជោគជ័យ!"];
                    } else {
                        // Handle duplicate key error gracefully if DB still enforces UNIQUE on name
                        if ($stmt->errno == 1062) {
                            $response = ['status' => 'error', 'message' => "Database មាន UNIQUE លើឈ្មោះទីតាំង។ ដើម្បីអនុញ្ញាតឲ្យឈ្មោះស្ទួន សូមរត់ SQL នៅ 'db/allow_duplicate_location_names.sql' ហើយសាកល្បងម្តងទៀត។"];
                        } else {
                            $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការកែសម្រួលទីតាំង: " . $stmt->error];
                        }
                    }
                    $stmt->close();
                }
                break;

			case 'assign_user_location':
				$employee_ids = $_POST['employee_ids'] ?? [];
				$location_ids = $_POST['location_ids'] ?? [];
				$custom_radius = (int)($_POST['custom_radius_meters'] ?? 100);

				if (empty($employee_ids) || empty($location_ids)) {
					$response = ['status' => 'error', 'message' => "សូមជ្រើសរើសបុគ្គលិកយ៉ាងតិចម្នាក់ និងទីតាំងយ៉ាងតិចមួយ!"];
					break;
				}

				$sql = "INSERT INTO user_locations (employee_id, location_id, custom_radius_meters, created_by_admin_id) VALUES (?, ?, ?, ?)
							ON DUPLICATE KEY UPDATE custom_radius_meters = VALUES(custom_radius_meters)";

				if ($stmt = $mysqli->prepare($sql)) {
					$success_count = 0;
					$error_count = 0;

					foreach ($employee_ids as $employee_id) {
						foreach ($location_ids as $location_id) {
							$stmt->bind_param("siis", $employee_id, $location_id, $custom_radius, $current_admin_id);
							if ($stmt->execute()) {
								$success_count++;
							} else {
								$error_count++;
							}
						}
					}
					$stmt->close();

					$message = "បានបង្កើត/Update ការកំណត់ចំនួន **{$success_count}** ដោយជោគជ័យ។";
					if ($error_count > 0) {
						$message .= " មានកំហុសក្នុងការបង្កើត/អัปដេតការកំណត់ **{$error_count}** ផងដែរ។";
					}
					$response = ['status' => 'success', 'message' => $message];
				} else {
					$response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការត្រៀម Query: " . $mysqli->error];
				}
				break;

			case 'delete_location':
				$loc_id = (int)($_POST['loc_id'] ?? 0);
                $sql = "DELETE FROM locations WHERE id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("isi", $loc_id, $current_admin_id, $is_super_admin);
                    if ($stmt->execute()) {
                        // Also delete any assignments from user_locations, with safe prepared statements
                        if ($is_super_admin) {
                            if ($del = $mysqli->prepare("DELETE FROM user_locations WHERE location_id = ?")) {
                                $del->bind_param("i", $loc_id);
                                $del->execute();
                                $del->close();
                            }
                        } else {
                            if ($del = $mysqli->prepare("DELETE FROM user_locations WHERE location_id = ? AND created_by_admin_id = ?")) {
                                $del->bind_param("is", $loc_id, $current_admin_id);
                                $del->execute();
                                $del->close();
                            }
                        }
                        $response = ['status' => 'success', 'message' => "ទីតាំងត្រូវបានលុបដោយជោគជ័យ!"];
                    } else {
                        $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការលុបទីតាំង: " . $stmt->error];
                    }
                    $stmt->close();
                }
				break;

			case 'unassign_location':
				$assign_id = (int)($_POST['assign_id'] ?? 0);
				$sql = "DELETE FROM user_locations WHERE id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
				if ($stmt = $mysqli->prepare($sql)) {
					$stmt->bind_param("isi", $assign_id, $current_admin_id, $is_super_admin);
					if ($stmt->execute()) { $response = ['status' => 'success', 'message' => "ការកំណត់ទីតាំងត្រូវបានលុបចោលដោយជោគជ័យ!"]; }
					else { $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការលុបចោល: " . $stmt->error]; }
					$stmt->close();
				}
				break;

			case 'revoke_token':
                $revoke_token = $_POST['token'] ?? '';
                // Permission: Super Admin can revoke any; normal admin only their users or themselves
                $can_revoke = false;
                $check_sql = "SELECT u.employee_id FROM active_tokens at JOIN users u ON at.employee_id = u.employee_id WHERE at.auth_token = ?";
                if ($stmt = $mysqli->prepare($check_sql)) {
                    $stmt->bind_param("s", $revoke_token);
                    $stmt->execute();
                    $res = $stmt->get_result();
                    if ($row = $res->fetch_assoc()) {
                        $token_emp = $row['employee_id'];
                        if ($is_super_admin || $token_emp === $current_admin_id) {
                            $can_revoke = true;
                        } else {
                            // Check ownership by admin
                            $own_sql = "SELECT 1 FROM users WHERE employee_id = ? AND created_by_admin_id = ? LIMIT 1";
                            if ($own_stmt = $mysqli->prepare($own_sql)) {
                                $own_stmt->bind_param("ss", $token_emp, $current_admin_id);
                                $own_stmt->execute();
                                $own_res = $own_stmt->get_result();
                                $can_revoke = ($own_res && $own_res->num_rows > 0);
                                $own_stmt->close();
                            }
                        }
                    }
                    $stmt->close();
                }

                if (!$can_revoke) { $response = ['status' => 'error', 'message' => 'Permission denied to revoke this token.']; break; }

                $sql = "DELETE FROM active_tokens WHERE auth_token = ?";
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("s", $revoke_token);
                    if ($stmt->execute()) { $response = ['status' => 'success', 'message' => "Token ត្រូវបានលុបចោល (Revoked) ដោយជោគជ័យ! User នោះនឹងត្រូវបាន Log Out ដោយស្វ័យប្រវត្តិ។"]; if(isset($token_emp)){ log_user_event($mysqli,$token_emp,'token_revoke'); } }
                    else { $response = ['status' => 'error', 'message' => "មានកំហុសក្នុងការលុប Token: " . $stmt->error]; }
                    $stmt->close();
                }
				break;

            case 'revoke_user_tokens':
                // NEW: Revoke ALL tokens for a specific employee_id (self or owned user). Super admin can revoke any.
                $target_emp = trim($_POST['employee_id'] ?? '');
                if ($target_emp === '') { $response = ['status' => 'error', 'message' => 'Employee ID required.']; break; }

                $can_revoke_all = false;
                if ($is_super_admin || $target_emp === $current_admin_id) {
                    $can_revoke_all = true;
                } else {
                    // verify ownership (created_by_admin_id)
                    if ($own_stmt = $mysqli->prepare("SELECT 1 FROM users WHERE employee_id = ? AND created_by_admin_id = ? LIMIT 1")) {
                        $own_stmt->bind_param('ss', $target_emp, $current_admin_id);
                        $own_stmt->execute();
                        $own_res = $own_stmt->get_result();
                        $can_revoke_all = ($own_res && $own_res->num_rows > 0);
                        $own_stmt->close();
                    }
                }

                if (!$can_revoke_all) {
                    $response = ['status' => 'error', 'message' => 'Permission denied to revoke tokens for this employee.'];
                    break;
                }

                if ($del = $mysqli->prepare('DELETE FROM active_tokens WHERE employee_id = ?')) {
                    $del->bind_param('s', $target_emp);
                    if ($del->execute()) {
                        $affected = $del->affected_rows;
                        $response = ['status' => 'success', 'message' => "Revoked {$affected} active token(s) for {$target_emp}."];
                        log_user_event($mysqli,$target_emp,'token_revoke_all');
                    } else {
                        $response = ['status' => 'error', 'message' => 'Failed to revoke tokens: ' . $del->error];
                    }
                    $del->close();
                } else {
                    $response = ['status' => 'error', 'message' => 'DB prepare error while revoking tokens: ' . $mysqli->error];
                }
                break;

            case 'update_user_status':
                // Update employment_status and optional leave_date; revoke tokens if not Active
                if (!(hasPageAccess($mysqli,'users','list_users',$admin_id_check) || hasPageAccess($mysqli,'users','create_user',$admin_id_check))) { $response=['status'=>'error','message'=>'Access denied']; break; }
                $emp = trim($_POST['employee_id'] ?? '');
                $new_status = $_POST['employment_status'] ?? '';
                $leave_date_raw = trim($_POST['leave_date'] ?? '');
                if ($emp==='') { $response=['status'=>'error','message'=>'Missing employee_id']; break; }
                if (!in_array($new_status,['Active','Suspended','Resigned'],true)) { $response=['status'=>'error','message'=>'Invalid status']; break; }
                $scoped_ok = false;
                if ($is_super_admin) { $scoped_ok = true; }
                else { if ($st = $mysqli->prepare("SELECT 1 FROM users WHERE employee_id = ? AND created_by_admin_id = ? LIMIT 1")) { $st->bind_param('ss',$emp,$current_admin_id); $st->execute(); $r=$st->get_result(); $scoped_ok = ($r && $r->num_rows>0); $st->close(); } }
                if (!$scoped_ok) { $response=['status'=>'error','message'=>'Permission denied for this employee']; break; }
                $use_leave=false; $leave_date_param=null;
                if ($leave_date_raw!=='') { $ts=strtotime($leave_date_raw); if($ts!==false){ $leave_date_param=date('Y-m-d',$ts); $use_leave=true; } }
                if ($use_leave) { if ($stmt=$mysqli->prepare("UPDATE users SET employment_status=?, leave_date=? WHERE employee_id=?")) { $stmt->bind_param('sss',$new_status,$leave_date_param,$emp); $ok=$stmt->execute(); $err=$stmt->error; $stmt->close(); } }
                else { if ($stmt=$mysqli->prepare("UPDATE users SET employment_status=?, leave_date=NULL WHERE employee_id=?")) { $stmt->bind_param('ss',$new_status,$emp); $ok=$stmt->execute(); $err=$stmt->error; $stmt->close(); } }
                if (empty($ok)) { $response=['status'=>'error','message'=>'Update failed: '.($err??'')]; break; }
                if ($new_status!=='Active') { if ($del=$mysqli->prepare('DELETE FROM active_tokens WHERE employee_id=?')) { $del->bind_param('s',$emp); $del->execute(); $del->close(); } }
                log_user_event($mysqli,$emp,'status_change');
                $response=['status'=>'success','message'=>'Employment status updated'];
                break;

            case 'save_panel_settings':
                $title = $_POST['panel_title'] ?? 'Admin Panel';
                $show_title = isset($_POST['show_title_with_logo']) ? '1' : '0';
                $footer_text = $_POST['footer_text'] ?? '';

                $mysqli->begin_transaction();
                try {
                    // Save Title
                    $sql_title = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES (?, 'panel_title', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
                    $stmt_title = $mysqli->prepare($sql_title);
                    $stmt_title->bind_param("ss", $current_admin_id, $title);
                    $stmt_title->execute();
                    $stmt_title->close();

                    // Save Show Title Toggle
                    $sql_show_title = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES (?, 'show_title_with_logo', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
                    $stmt_show_title = $mysqli->prepare($sql_show_title);
                    $stmt_show_title->bind_param("ss", $current_admin_id, $show_title);
                    $stmt_show_title->execute();
                    $stmt_show_title->close();

                    // Save Footer Text
                    $sql_footer = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES (?, 'footer_text', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
                    $stmt_footer = $mysqli->prepare($sql_footer);
                    $stmt_footer->bind_param("ss", $current_admin_id, $footer_text);
                    $stmt_footer->execute();
                    $stmt_footer->close();

                    $logo_message = '';
                    if (isset($_FILES['panel_logo']) && $_FILES['panel_logo']['error'] == 0) {
                        $allowed_types = ['image/png', 'image/jpeg', 'image/gif', 'image/svg+xml'];
                        if (in_array($_FILES['panel_logo']['type'], $allowed_types)) {
                            if (!is_dir('uploads')) { mkdir('uploads', 0755, true); }

                            $file_extension = strtolower(pathinfo($_FILES['panel_logo']['name'], PATHINFO_EXTENSION));
                            $new_filename = 'logo_' . $current_admin_id . '_' . time() . '.' . $file_extension;
                            $destination = 'uploads/' . $new_filename;

                            $old_logo_path = get_setting($mysqli, $current_admin_id, 'panel_logo_path', '');
                            if (!empty($old_logo_path) && file_exists($old_logo_path)) {
                                @unlink($old_logo_path);
                            }

                            if (compressAndMoveImage($_FILES['panel_logo']['tmp_name'], $destination, 75, 1200, 1200)) {
                                $sql_logo = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES (?, 'panel_logo_path', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)";
                                $stmt_logo = $mysqli->prepare($sql_logo);
                                $stmt_logo->bind_param("ss", $current_admin_id, $destination);
                                $stmt_logo->execute();
                                $stmt_logo->close();
                                $logo_message = ' Logo ត្រូវបាន Upload ដោយជោគជ័យ។';
                            } else {
                                throw new Exception('មានបញ្ហាក្នុងការ Upload Logo។');
                            }
                        } else {
                            throw new Exception('ប្រភេទ File របស់ Logo មិនត្រឹមត្រូវ។');
                        }
                    }

                    $mysqli->commit();
                    $response = ['status' => 'success', 'message' => 'ការកំណត់ Panel ត្រូវបានរក្សាទុក។' . $logo_message];

                } catch (Exception $e) {
                    $mysqli->rollback();
                    $response = ['status' => 'error', 'message' => 'មានកំហុសក្នុងការរក្សាទុក: ' . $e->getMessage()];
                }
                break;

            case 'batch_compress_existing_images':
                if (!hasPageAccess($mysqli, 'settings', 'panel_settings', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied.'];
                    break;
                }
                @set_time_limit(300); // Allow up to 5 minutes

                /**
                 * Compress a single image file in-place.
                 * @param string $path      Full path to image
                 * @param int    $maxWidth  Max output width in px
                 * @param int    $maxHeight Max output height in px
                 * @param int    $quality   JPEG/WebP quality (0-100)
                 * @param int    $skipBytes Skip compression if file already < this bytes
                 * @return bool  true = compressed, false = skipped or error
                 */
                $process_image = function(string $path, int $maxWidth, int $maxHeight, int $quality, int $skipBytes) {
                    if (!is_file($path)) return false;
                    $info = @getimagesize($path);
                    if (!$info) return false;

                    $mime   = $info['mime'];
                    $width  = (int)$info[0];
                    $height = (int)$info[1];
                    $fileSize = filesize($path);

                    // Skip if already small enough
                    if ($fileSize < $skipBytes && $width <= $maxWidth && $height <= $maxHeight) {
                        return false;
                    }

                    // Compute new dimensions preserving aspect ratio
                    $newWidth  = $width;
                    $newHeight = $height;
                    if ($width > $maxWidth || $height > $maxHeight) {
                        $ratio = $width / $height;
                        if ($ratio >= 1) { // landscape / square
                            $newWidth  = $maxWidth;
                            $newHeight = (int)round($maxWidth / $ratio);
                        } else { // portrait
                            $newHeight = $maxHeight;
                            $newWidth  = (int)round($maxHeight * $ratio);
                        }
                    }

                    // Load source image
                    $srcImg = null;
                    switch ($mime) {
                        case 'image/jpeg': $srcImg = @imagecreatefromjpeg($path); break;
                        case 'image/png':  $srcImg = @imagecreatefrompng($path);  break;
                        case 'image/webp': $srcImg = @imagecreatefromwebp($path); break;
                        default: return false;
                    }
                    if (!$srcImg) return false;

                    // Create destination canvas
                    $newImg = imagecreatetruecolor($newWidth, $newHeight);
                    // Preserve transparency for PNG/WebP
                    if ($mime === 'image/png' || $mime === 'image/webp') {
                        imagecolortransparent($newImg, imagecolorallocatealpha($newImg, 0, 0, 0, 127));
                        imagealphablending($newImg, false);
                        imagesavealpha($newImg, true);
                    } else {
                        // White background for JPEG (no alpha)
                        $white = imagecolorallocate($newImg, 255, 255, 255);
                        imagefilledrectangle($newImg, 0, 0, $newWidth, $newHeight, $white);
                    }

                    imagecopyresampled($newImg, $srcImg, 0, 0, 0, 0, $newWidth, $newHeight, $width, $height);

                    // Save back to same path
                    $saved = false;
                    switch ($mime) {
                        case 'image/jpeg': $saved = imagejpeg($newImg, $path, $quality); break;
                        case 'image/png':  $saved = imagepng($newImg, $path, 7); break;   // 0-9; 7=good compression
                        case 'image/webp': $saved = imagewebp($newImg, $path, $quality); break;
                    }

                    imagedestroy($srcImg);
                    imagedestroy($newImg);
                    return $saved;
                };

                // ── Directory configs ──────────────────────────────────────────
                // Avatars are profile pictures — displayed small, so 400×400 is plenty
                // General uploads (logos, etc.) allow 800×800
                $dir_configs = [
                    'uploads/avatars/' => ['maxW' => 400,  'maxH' => 400,  'quality' => 78, 'skip' => 80  * 1024], // skip if <80KB
                    'uploads/'         => ['maxW' => 800,  'maxH' => 800,  'quality' => 80, 'skip' => 200 * 1024], // skip if <200KB
                ];

                $totalFiles    = 0;
                $totalProcessed = 0;
                $totalSkipped  = 0;
                $totalSaved    = 0; // bytes saved
                $details       = [];

                foreach ($dir_configs as $dir => $cfg) {
                    if (!is_dir($dir)) continue;
                    // Only files directly in this dir (non-recursive) — avatars/ is already separate
                    $pattern = $dir . '*.{jpg,jpeg,png,webp,JPG,JPEG,PNG,WEBP}';
                    $files   = glob($pattern, GLOB_BRACE) ?: [];

                    $dirProcessed = 0; $dirSkipped = 0; $dirSaved = 0;

                    foreach ($files as $file) {
                        if (!is_file($file)) continue;
                        $before = filesize($file);
                        $result = $process_image($file, $cfg['maxW'], $cfg['maxH'], $cfg['quality'], $cfg['skip']);
                        clearstatcache(true, $file);
                        $after = filesize($file);

                        if ($result) { $dirProcessed++; $dirSaved += ($before - $after); }
                        else         { $dirSkipped++; }
                        $totalFiles++;
                    }

                    $totalProcessed += $dirProcessed;
                    $totalSkipped   += $dirSkipped;
                    $totalSaved     += $dirSaved;
                    $details[] = sprintf('%s → Compressed: %d, Skipped: %d, Saved: %.2f MB',
                        $dir, $dirProcessed, $dirSkipped, $dirSaved / 1048576);
                }

                $savedMBTotal = number_format($totalSaved / 1048576, 2);
                $response = [
                    'status'  => 'success',
                    'message' => "✅ ដំណើរការ {$totalFiles} រូបភាព — Compressed: {$totalProcessed}, Skipped: {$totalSkipped}. "
                               . "ចំណេញទំហំ: {$savedMBTotal} MB. " . implode(' | ', $details)
                ];
                break;

            case 'save_login_page_settings':
                if (!hasPageAccess($mysqli, 'settings', 'login_page_settings', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'អ្នកមិនមានសិទ្ធិរក្សាទុកការកំណត់នេះទេ។'];
                    break;
                }

                $mysqli->begin_transaction();
                try {
                    // Save title and icon class
                    update_system_setting($mysqli, 'login_page_title', $_POST['login_page_title'] ?? 'Admin Panel Login');
                    update_system_setting($mysqli, 'login_page_icon_class', $_POST['login_page_icon_class'] ?? 'fa-solid fa-user-shield');

                    $logo_message = '';
                    // Handle file upload
                    if (isset($_FILES['login_page_logo']) && $_FILES['login_page_logo']['error'] == 0) {
                        $allowed_types = ['image/png', 'image/jpeg', 'image/gif', 'image/svg+xml'];
                        if (in_array($_FILES['login_page_logo']['type'], $allowed_types)) {
                            if (!is_dir('uploads')) { mkdir('uploads', 0755, true); }

                            $file_extension = pathinfo($_FILES['login_page_logo']['name'], PATHINFO_EXTENSION);
                            $new_filename = 'login_logo_SYSTEM_WIDE_' . time() . '.' . $file_extension;
                            $destination = 'uploads/' . $new_filename;

                            // Delete old logo if it exists
                            $old_logo_path = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_logo_path', '');
                            if (!empty($old_logo_path) && file_exists($old_logo_path)) {
                                @unlink($old_logo_path);
                            }

                            if (compressAndMoveImage($_FILES['login_page_logo']['tmp_name'], $destination, 75, 1200, 1200)) {
                                // Save new logo path to DB
                                update_system_setting($mysqli, 'login_page_logo_path', $destination);
                                $logo_message = ' Logo សម្រាប់ Login Page ត្រូវបាន Upload ដោយជោគជ័យ។';
                            } else {
                                throw new Exception('មានបញ្ហាក្នុងការ Upload Logo។');
                            }
                        } else {
                            throw new Exception('ប្រភេទ File របស់ Logo មិនត្រឹមត្រូវ។');
                        }
                    }

                    $mysqli->commit();
                    $response = ['status' => 'success', 'message' => 'ការកំណត់ Login Page ត្រូវបានរក្សាទុក។' . $logo_message];

                } catch (Exception $e) {
                    $mysqli->rollback();
                    $response = ['status' => 'error', 'message' => 'មានកំហុសក្នុងការរក្សាទុក: ' . $e->getMessage()];
                }
                break;

            case 'save_menu_settings':
                $menu_order = $_POST['menu_order'] ?? [];
                $menu_text = $_POST['menu_text'] ?? [];
                $submenu_text = $_POST['submenu_text'] ?? [];

                $mysqli->begin_transaction();
                try {
                    $sql_main = "UPDATE sidebar_settings SET menu_order = ?, menu_text = ? WHERE menu_key = ? AND admin_id = ?";
                    if ($stmt_main = $mysqli->prepare($sql_main)) {
                        foreach ($menu_order as $key => $order) {
                            $text = $menu_text[$key] ?? $key;
                            $stmt_main->bind_param("isss", $order, $text, $key, $current_admin_id);
                            $stmt_main->execute();
                        }
                        $stmt_main->close();
                    } else {
                        throw new Exception("Main menu prepare failed: " . $mysqli->error);
                    }

                    $sql_sub = "UPDATE submenu_settings SET submenu_text = ? WHERE menu_key = ? AND action_key = ? AND admin_id = ?";
                    if($stmt_sub = $mysqli->prepare($sql_sub)){
                        foreach ($submenu_text as $menu_key => $actions) {
                            foreach ($actions as $action_key => $text) {
                                $stmt_sub->bind_param("ssss", $text, $menu_key, $action_key, $current_admin_id);
                                $stmt_sub->execute();
                            }
                        }
                        $stmt_sub->close();
                    } else {
                         throw new Exception("Submenu prepare failed: " . $mysqli->error);
                    }

                    $mysqli->commit();
                    $response = ['status' => 'success', 'message' => 'ការកំណត់ Sidebar Menu ត្រូវបានរក្សាទុកដោយជោគជ័យ។'];
                } catch (Exception $e) {
                    $mysqli->rollback();
                    $response = ['status' => 'error', 'message' => 'Database error: ' . $e->getMessage()];
                }

                break;

            case 'save_sidebar_visibility':
                // Gather selected hidden pages/actions
                $hide_pages = $_POST['hide_page'] ?? [];
                $hide_actions = $_POST['hide_action'] ?? [];
                $all_hide = [];
                foreach ($hide_pages as $p) { $p = trim($p); if ($p !== '') { $all_hide[] = $p; } }
                foreach ($hide_actions as $pa) { $pa = trim($pa); if ($pa !== '') { $all_hide[] = $pa; } }
                // Deduplicate
                $all_hide = array_values(array_unique($all_hide));
                // Persist as JSON setting per admin
                $json_val = json_encode($all_hide, JSON_UNESCAPED_UNICODE);
                if ($set_stmt = $mysqli->prepare("INSERT INTO system_settings (setting_key, setting_value) VALUES (?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)")) {
                    $key = $current_admin_id . '_sidebar_hidden_items';
                    $set_stmt->bind_param('ss', $key, $json_val);
                    if ($set_stmt->execute()) {
                        $response = ['status'=>'success','message'=>'Sidebar visibility settings saved'];
                    } else {
                        $response = ['status'=>'error','message'=>'Failed to save visibility: '.$set_stmt->error];
                    }
                    $set_stmt->close();
                } else {
                    $response = ['status'=>'error','message'=>'DB prepare failed: '.$mysqli->error];
                }
                break;

               case 'save_app_scan_settings':
                if (!hasPageAccess($mysqli, 'settings', 'manage_app_scan', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'អ្នកមិនមានសិទ្ធិរក្សាទុកការកំណត់នេះទេ។'];
                    break;
                }

                $mysqli->begin_transaction();
                try {
                    // 1. Save all text inputs for the current admin
                    $settings_to_save = [
                        // Base header (keep header_type + base title/subtitle for fallback only)
                        'header_type','header_title','header_subtitle',
                        // Typed label/header overrides Skill (base label inputs removed; overrides now primary)
                        'header_title__skill','header_subtitle__skill','greeting_text__skill','label_attendance__skill','label_request_form__skill','label_my_requests__skill','label_view_logs__skill','label_profile__skill',
                        // Typed label/header overrides Worker
                        'header_title__worker','header_subtitle__worker','greeting_text__worker','label_attendance__worker','label_request_form__worker','label_my_requests__worker','label_view_logs__worker','label_profile__worker',
                        // Telegram base + typed tokens/chat IDs
                        'telegram_bot_token','telegram_chat_id','telegram_bot_token__skill','telegram_chat_id__skill','telegram_bot_token__worker','telegram_chat_id__worker',
                        // Templates + time format (base only)
                        'telegram_tpl_attendance','telegram_tpl_request','telegram_time_format',
                        // Status icons (base only)
                        'status_icon_good','status_icon_late',
                        // Department allow-lists
                        'allowed_departments_skill','allowed_departments_worker',
                        // Manual Scan Modes and Users (text inputs)
                        'manual_scan_mode__skill', 'manual_scan_specific_users__skill',
                        'manual_scan_mode__worker', 'manual_scan_specific_users__worker'
                    ];
                    foreach ($settings_to_save as $key) {
                        // Only update keys that are present in POST to avoid wiping values for fields not shown in UI
                        if (array_key_exists($key, $_POST)) {
                            update_app_scan_setting($mysqli, $current_admin_id, $key, $_POST[$key]);
                        }
                    }

                    // 2. Save checkbox values for the current admin
                    $checkboxes = [
                        // Typed visibility Skill (base removed)
                        'show_attendance_card__skill','show_request_form_card__skill','show_my_requests_card__skill','show_view_logs_card__skill','show_profile_footer__skill','show_home_footer__skill',
                        // Typed visibility Worker
                        'show_attendance_card__worker','show_request_form_card__worker','show_my_requests_card__worker','show_view_logs_card__worker','show_profile_footer__worker','show_home_footer__worker',
                        // Telegram notify flags base + Worker (Skill overrides UI removed)
                        'telegram_notify_attendance','telegram_notify_requests','telegram_notify_attendance__worker','telegram_notify_requests__worker'
                    ];
                    foreach ($checkboxes as $key) {
                        $value = isset($_POST[$key]) ? '1' : '0';
                        // កែប្រែ៖ បញ្ជូន $current_admin_id ចូលไป
                        update_app_scan_setting($mysqli, $current_admin_id, $key, $value);
                    }

                    // 3. Handle file upload for the logo
                    $logo_message = '';
                    if (isset($_FILES['header_logo']) && $_FILES['header_logo']['error'] == 0) {
                        $allowed_types = ['image/png', 'image/jpeg', 'image/gif', 'image/svg+xml'];
                        if (in_array($_FILES['header_logo']['type'], $allowed_types)) {
                            if (!is_dir('uploads')) { mkdir('uploads', 0755, true); }

                            $file_extension = pathinfo($_FILES['header_logo']['name'], PATHINFO_EXTENSION);
                            // កែប្រែ៖ ตั้งชื่อไฟล์ให้เฉพาะสำหรับ Admin คนนั้นๆ
                            $new_filename = 'app_scan_logo_' . $current_admin_id . '_' . time() . '.' . $file_extension;
                            $destination = 'uploads/' . $new_filename;

                            // កែប្រែ៖ ลบโลโก้เก่าของ Admin คนนี้ (ถ้ามี)
                            $old_logo_path = get_app_scan_setting($mysqli, $current_admin_id, 'header_logo_path', '');
                            if (!empty($old_logo_path) && file_exists($old_logo_path)) {
                                @unlink($old_logo_path);
                            }

                            if (compressAndMoveImage($_FILES['header_logo']['tmp_name'], $destination, 75, 1200, 1200)) {
                                // កែប្រែ៖ บันทึก Path ของโลโก้ใหม่សម្រាប់ Admin คนนี้
                                update_app_scan_setting($mysqli, $current_admin_id, 'header_logo_path', $destination);
                                $logo_message = ' Logo សម្រាប់ App Scan ត្រូវបាន Upload ដោយជោគជ័យ។';
                            } else {
                                throw new Exception('មានបញ្ហាក្នុងការ Upload Logo។');
                            }
                        } else {
                            throw new Exception('ប្រភេទ File របស់ Logo មិនត្រឹមត្រូវ។');
                        }
                    }

                    $mysqli->commit();
                    $response = ['status' => 'success', 'message' => 'ការកំណត់ App Scan ត្រូវបានរក្សាទុក។' . $logo_message];

                } catch (Exception $e) {
                    $mysqli->rollback();
                    $response = ['status' => 'error', 'message' => 'មានកំហុសក្នុងការរក្សាទុក: ' . $e->getMessage()];
                }
                break;

			case 'get_reports_data':
				// Fetch updated reports data for auto-update
				$filter_date = $_POST['filter_date'] ?? date('Y-m-d');
				$filter_status = $_POST['filter_status'] ?? 'All';
				$filter_department = $_POST['filter_department'] ?? 'department';
				$current_p_page = isset($_POST['p']) ? (int)$_POST['p'] : 1;
				if ($current_p_page < 1) { $current_p_page = 1; }
				$records_per_page = 15;
				$offset = ($current_p_page - 1) * $records_per_page;

				// Get dynamic headers
				$dynamic_headers = [];
				$fields_sql = "SELECT field_key, field_label FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC";
				if ($fields_stmt = $mysqli->prepare($fields_sql)) {
					$fields_stmt->bind_param("s", $current_admin_id);
					$fields_stmt->execute();
					$fields_result = $fields_stmt->get_result();
					while ($field_row = $fields_result->fetch_assoc()) {
						$dynamic_headers[$field_row['field_key']] = $field_row['field_label'];
					}
					$fields_stmt->close();
				}

				// Build query
				$sql = "SELECT cl.*, u.custom_data, cl.custom_fields_data, u.name
						FROM checkin_logs cl
						LEFT JOIN users u ON cl.employee_id = u.employee_id
						WHERE DATE(cl.log_datetime) = ?";
				$params = [$filter_date];
				$types = "s";

				if ($filter_status !== 'All') {
					$sql .= " AND cl.status = ?";
					$params[] = $filter_status;
					$types .= "s";
				}
				if ($filter_department === 'worker') {
					$sql .= " AND JSON_EXTRACT(u.custom_data, '$.department') = ?";
					$params[] = 'Worker';
					$types .= "s";
				} elseif ($filter_department === 'department') {
					$sql .= " AND (JSON_EXTRACT(u.custom_data, '$.department') != ? OR JSON_EXTRACT(u.custom_data, '$.department') IS NULL)";
					$params[] = 'Worker';
					$types .= "s";
				}
				if (!$is_super_admin) {
					$sql .= " AND u.created_by_admin_id = ?";
					$params[] = $current_admin_id;
					$types .= "s";
				}

				$sql .= " ORDER BY u.name ASC, cl.log_datetime ASC LIMIT ? OFFSET ?";
				$params[] = $records_per_page;
				$params[] = $offset;
				$types .= "ii";

				$report_data = [];
				if ($stmt = $mysqli->prepare($sql)) {
					$stmt->bind_param($types, ...$params);
					$stmt->execute();
					$report_data = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
					$stmt->close();
				}

				// Build tbody HTML
				$tbody_html = '';
				if (empty($report_data)) {
					$colspan = 10 + count($dynamic_headers);
					$tbody_html = "<tr><td colspan='{$colspan}' style='text-align: center; font-style: italic;'>មិនមានទិន្នន័យវត្តមានសម្រាប់ថ្ងៃដែលបានជ្រើសរើសទេ។</td></tr>";
				} else {
					foreach ($report_data as $log) {
						$saved_custom_data = json_decode($log['custom_fields_data'] ?? '{}', true);
						$log_pk_val = (int)($log['id'] ?? $log['log_id'] ?? $log['checkin_id'] ?? 0);

						// Calculate late minutes if Late
						$late_status_minutes = null;
						if (isset($log['status']) && strcasecmp($log['status'], 'Late') === 0) {
							// Prefer stored late_minutes if available
							if (isset($log['late_minutes']) && (int)$log['late_minutes'] > 0) {
								$late_status_minutes = (int)$log['late_minutes'];
							} else {
								$empIdCalc = $log['employee_id'];
								$current_hms = date('H:i:s', strtotime($log['log_datetime']));
								$pivot_time_row = '';
								if ($stmt_pv_r = $mysqli->prepare("SELECT end_time FROM attendance_rules WHERE employee_id = ? AND type = 'checkin' AND status = 'Good' AND end_time <= ? ORDER BY end_time DESC LIMIT 1")) {
									$stmt_pv_r->bind_param('sss', $empIdCalc, 'checkin', $current_hms);
									if ($stmt_pv_r->execute()) {
										$res_pv_r = $stmt_pv_r->get_result();
										if ($row_pv_r = $res_pv_r->fetch_assoc()) { $pivot_time_row = $row_pv_r['end_time']; }
									}
									$stmt_pv_r->close();
								}
								if ($pivot_time_row === '') {
									if ($stmt_ec_r = $mysqli->prepare("SELECT start_time FROM attendance_rules WHERE employee_id = ? AND type='checkin' ORDER BY start_time ASC LIMIT 1")) {
										$stmt_ec_r->bind_param('s', $empIdCalc);
										if ($stmt_ec_r->execute()) {
											$res_ec_r = $stmt_ec_r->get_result();
											if ($row_ec_r = $res_ec_r->fetch_assoc()) { $pivot_time_row = trim($row_ec_r['start_time'] ?? ''); }
										}
										$stmt_ec_r->close();
									}
								}
								if ($pivot_time_row !== '' && preg_match('/^\d{1,2}:\d{2}$/', $pivot_time_row)) { $pivot_time_row .= ':00'; }
								if ($pivot_time_row !== '') {
									$base_dt_row = date('Y-m-d', strtotime($log['log_datetime'])) . ' ' . $pivot_time_row;
									$late_secs_row = strtotime($log['log_datetime']) - strtotime($base_dt_row);
									if ($late_secs_row > 0) {
										// FIX: Use ceil for accuracy
										$late_status_minutes = (int)ceil($late_secs_row / 60);
									}
								}
							}
						}

						$status_class = (strtolower($log['status'] ?? '') == 'late') ? 'status-late' : 'status-good';
						$status_icon = (strtolower($log['status'] ?? '') == 'late') ? '<i class="fa-solid fa-hourglass-end"></i> ' : '<i class="fa-solid fa-circle-check"></i> ';
						$status_text_render = htmlspecialchars($log['status'] ?? 'Good');
						if ($late_status_minutes !== null) { $status_text_render .= ' (' . format_late_minutes($late_status_minutes) . ')'; }

						$tbody_html .= "<tr data-log-pk='{$log_pk_val}' data-emp='" . htmlspecialchars($log['employee_id']) . "' data-dt='" . htmlspecialchars($log['log_datetime']) . "'>";
						$tbody_html .= "<td style='text-align:center;'><input type='checkbox' class='report-select' data-id='{$log_pk_val}'></td>";
						$tbody_html .= "<td>" . htmlspecialchars($log['employee_id']) . "</td>";
						$tbody_html .= "<td style='font-weight: bold; font-size:18px; color: #004085;'>" . htmlspecialchars($log['name']) . "</td>";
						$tbody_html .= "<td class='col-location_name'>" . htmlspecialchars($log['location_name'] ?? '') . "</td>";

						foreach ($dynamic_headers as $key => $label) {
							$value = htmlspecialchars($saved_custom_data[$key] ?? $saved_custom_data[$label] ?? 'N/A');
							$tbody_html .= "<td>{$value}</td>";
						}

						$tbody_html .= "<td>" . htmlspecialchars($log['action_type']) . "</td>";
						$tbody_html .= "<td>" . date('d/m/Y', strtotime($log['log_datetime'])) . "</td>";
						$tbody_html .= "<td>" . date('h:i:s A', strtotime($log['log_datetime'])) . "</td>";
						// Location column moved from here
						$tbody_html .= "<td><span class='{$status_class}'>{$status_icon}{$status_text_render}</span></td>";
						$tbody_html .= "<td class='late-reason-cell'>" . htmlspecialchars($log['late_reason'] ?? 'N/A') . "</td>";
						$tbody_html .= "<td><button type='button' class='btn btn-primary btn-sm edit-late-reason' data-log-id='{$log_pk_val}' data-emp-id='" . htmlspecialchars($log['employee_id']) . "' data-log-dt='" . htmlspecialchars($log['log_datetime']) . "' data-current-reason='" . htmlspecialchars($log['late_reason'] ?? '', ENT_QUOTES, 'UTF-8') . "'><i class='fa-solid fa-pen-to-square'></i> View/Edit</button></td>";
						$tbody_html .= "</tr>";
					}
				}

				$response = ['status' => 'success', 'tbody_html' => $tbody_html];
				break;

            case 'send_notification':
                if (!hasPageAccess($mysqli, 'notifications', 'send_notifications', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied.'];
                    break;
                }

                $recipient_type = $_POST['recipient_type'] ?? '';
                $specific_users = $_POST['specific_users'] ?? [];
                $group_id = (int)($_POST['group_id'] ?? 0);
                $title = trim($_POST['notification_title'] ?? '');
                $message = trim($_POST['notification_message'] ?? '');
                $expiry_date = trim($_POST['expiry_date'] ?? '');

                if (empty($title) || empty($message)) {
                    $response = ['status' => 'error', 'message' => 'សូមបំពេញប្រធានបទ និងខ្លឹមសារការជូនដំណឹង។'];
                    break;
                }

                // Get recipients based on type
                $recipients = [];
                if ($recipient_type === 'all') {
                    $sql = "SELECT employee_id, name FROM users WHERE created_by_admin_id = ?";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("s", $current_admin_id);
                        $stmt->execute();
                        $result = $stmt->get_result();
                        while ($row = $result->fetch_assoc()) {
                            $recipients[] = $row;
                        }
                        $stmt->close();
                    }
                } elseif ($recipient_type === 'specific' && !empty($specific_users)) {
                    $placeholders = str_repeat('?,', count($specific_users) - 1) . '?';
                    $sql = "SELECT employee_id, name FROM users WHERE employee_id IN ($placeholders) AND created_by_admin_id = ?";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $params = array_merge($specific_users, [$current_admin_id]);
                        $stmt->bind_param(str_repeat('s', count($params)), ...$params);
                        $stmt->execute();
                        $result = $stmt->get_result();
                        while ($row = $result->fetch_assoc()) {
                            $recipients[] = $row;
                        }
                        $stmt->close();
                    }
                } elseif ($recipient_type === 'group' && $group_id > 0) {
                    $sql = "SELECT u.employee_id, u.name FROM users u
                            JOIN user_skill_groups g ON JSON_CONTAINS(u.custom_data, JSON_QUOTE(g.id), '$.group_id')
                            WHERE g.id = ? AND u.created_by_admin_id = ?";
                    if ($stmt = $mysqli->prepare($sql)) {
                        $stmt->bind_param("is", $group_id, $current_admin_id);
                        $stmt->execute();
                        $result = $stmt->get_result();
                        while ($row = $result->fetch_assoc()) {
                            $recipients[] = $row;
                        }
                        $stmt->close();
                    }
                }

                if (empty($recipients)) {
                    $response = ['status' => 'error', 'message' => 'មិនមានអ្នកទទួលដែលត្រូវនឹងលក្ខខណ្ឌទេ។'];
                    break;
                }

                // Create notifications table if not exists
                $create_table_sql = "CREATE TABLE IF NOT EXISTS notifications (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    admin_id VARCHAR(64) NOT NULL,
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    recipient_type ENUM('all', 'specific', 'group') NOT NULL,
                    recipient_info TEXT,
                    sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expiry_date DATETIME NULL,
                    status ENUM('sent', 'expired') DEFAULT 'sent'
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
                $mysqli->query($create_table_sql);

                // Create user_notifications table
                $create_user_table_sql = "CREATE TABLE IF NOT EXISTS user_notifications (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    notification_id INT NOT NULL,
                    employee_id VARCHAR(64) NOT NULL,
                    is_read TINYINT(1) DEFAULT 0,
                    read_at TIMESTAMP NULL,
                    FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci";
                $mysqli->query($create_user_table_sql);

                // Insert notification
                $recipient_info = '';
                if ($recipient_type === 'all') {
                    $recipient_info = 'អ្នកប្រើប្រាស់ទាំងអស់';
                } elseif ($recipient_type === 'specific') {
                    $recipient_info = 'អ្នកប្រើប្រាស់ជាក់លាក់ (' . count($recipients) . ' នាក់)';
                } elseif ($recipient_type === 'group') {
                    $group_name = 'Unknown Group';
                    if ($stmt = $mysqli->prepare("SELECT group_name FROM user_skill_groups WHERE id = ?")) {
                        $stmt->bind_param("i", $group_id);
                        $stmt->execute();
                        $result = $stmt->get_result();
                        if ($row = $result->fetch_assoc()) {
                            $group_name = $row['group_name'];
                        }
                        $stmt->close();
                    }
                    $recipient_info = 'ក្រុម: ' . $group_name;
                }

                $expiry_datetime = null;
                if (!empty($expiry_date)) {
                    $expiry_datetime = date('Y-m-d H:i:s', strtotime($expiry_date));
                }

                $insert_sql = "INSERT INTO notifications (admin_id, title, message, recipient_type, recipient_info, expiry_date) VALUES (?, ?, ?, ?, ?, ?)";
                $notification_id = null;
                if ($stmt = $mysqli->prepare($insert_sql)) {
                    $stmt->bind_param("ssssss", $current_admin_id, $title, $message, $recipient_type, $recipient_info, $expiry_datetime);
                    if ($stmt->execute()) {
                        $notification_id = $stmt->insert_id;
                    }
                    $stmt->close();
                }

                if (!$notification_id) {
                    $response = ['status' => 'error', 'message' => 'មានកំហុសក្នុងការរក្សាទុកការជូនដំណឹង។'];
                    break;
                }

                // Insert user notifications
                $user_insert_sql = "INSERT INTO user_notifications (notification_id, employee_id) VALUES (?, ?)";
                $success_count = 0;
                if ($stmt = $mysqli->prepare($user_insert_sql)) {
                    foreach ($recipients as $recipient) {
                        $stmt->bind_param("is", $notification_id, $recipient['employee_id']);
                        if ($stmt->execute()) {
                            $success_count++;
                            // NEW: Send real Web Push (works when browser is closed)
                            sendWebPushNotification($mysqli, $recipient['employee_id'], $title, $message);
                        }
                    }
                    $stmt->close();
                }

                $response = ['status' => 'success', 'message' => "ការជូនដំណឹងត្រូវបានផ្ញើទៅអ្នកប្រើប្រាស់ {$success_count} នាក់ដោយជោគជ័យ។"];
                break;

            case 'get_notifications_history':
                if (!hasPageAccess($mysqli, 'notifications', 'send_notifications', $current_admin_id)) {
                    $response = ['status' => 'error', 'message' => 'Permission Denied.'];
                    break;
                }

                $sql = "SELECT id, title, recipient_info, sent_at, status FROM notifications WHERE admin_id = ? ORDER BY sent_at DESC LIMIT 50";
                $data = [];
                if ($stmt = $mysqli->prepare($sql)) {
                    $stmt->bind_param("s", $current_admin_id);
                    $stmt->execute();
                    $result = $stmt->get_result();
                    while ($row = $result->fetch_assoc()) {
                        $data[] = [
                            'id' => $row['id'],
                            'title' => $row['title'],
                            'recipient_info' => $row['recipient_info'],
                            'sent_at' => date('d/m/Y H:i', strtotime($row['sent_at'])),
                            'status' => $row['status']
                        ];
                    }
                    $stmt->close();
                }

                $response = ['status' => 'success', 'data' => $data];
                break;

			default:
				$response = ['status' => 'error', 'message' => 'មិនស្គាល់ Action'];
				break;
		}
	} else {
		$response = ['status' => 'error', 'message' => 'អ្នកមិនបាន Log In! ឬ Session ID បាត់។'];
	}

	echo json_encode($response);
	exit;
}
// ----------------------------------------------------
// END AJAX HANDLER BLOCK
// ----------------------------------------------------


// ដំណើរការ Logout
if (isset($_GET['logout'])) {
	unset($_SESSION['admin_logged_in']);
	unset($_SESSION['admin_id']);
	unset($_SESSION['admin_name']);
	unset($_SESSION['is_super_admin']); // លុប Session ថ្មី
    // Clear sub user session data if present
    unset($_SESSION['sub_user_logged_in']);
    unset($_SESSION['sub_user_parent_id']);
    unset($_SESSION['sub_user_id']);
    unset($_SESSION['sub_user_name']);
    unset($_SESSION['sub_user_permissions']);
    unset($_SESSION['combined_admin_sub_mode']);

    // If a remember cookie exists for admin, remove its token from DB and clear cookie
    if (!empty($_COOKIE['remember_admin'])) {
        list($selector, ) = explode(':', $_COOKIE['remember_admin'], 2);
        if (!empty($selector) && $stmt = $mysqli->prepare("DELETE FROM auth_tokens WHERE selector = ?")) {
            $stmt->bind_param('s', $selector);
            $stmt->execute();
            $stmt->close();
        }
        setcookie('remember_admin', '', time() - 3600, '/');
    }

    session_destroy();
	ob_end_clean();
	header("Location: admin_attendance.php");
	exit;
}

// ពេលមិនទាន់ Login គឺកំណត់ទៅជា 'login'
$current_page = $_GET['page'] ?? 'login';
$current_action = $_GET['action'] ?? $current_page; // Set default action for page check

// ពិនិត្យ Login មុននឹងបន្តទៅ Logic
$show_admin_pages = checkAdminLogin($mysqli);
$is_super_admin = isSuperAdmin();

// Load Login Page settings before checking if the user is logged in
$login_page_title = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_title', 'Admin Panel Login');
$login_page_logo_path = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_logo_path', '');
$login_page_icon_class = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_icon_class', 'fa-solid fa-user-shield');

if ($show_admin_pages) {
    $current_admin_id = $_SESSION['admin_id'];

    // ពិនិត្យ Subscription នៅគ្រប់ Page Load ទាំងអស់សម្រាប់អ្នកដែល Logged In
    $access_check = checkAccessExpiry($mysqli, $current_admin_id);

    // 1. បើផុតកំណត់ (Expired) គឺត្រូវ Log Out ភ្លាមៗ
    if ($access_check['status'] === 'expired') {
        unset($_SESSION['admin_logged_in']);
        unset($_SESSION['admin_id']);
        unset($_SESSION['admin_name']);
        unset($_SESSION['is_super_admin']);
        session_destroy();
        ob_end_clean();
        // បញ្ជូនទៅหน้า Login វិញជាមួយសារផុតកំណត់
        header("Location: admin_attendance.php?expired_msg=" . urlencode($access_check['message']));
        exit;
    }

    // 2. បើជិតផុតកំណត់ (Warning) គឺត្រូវបង្ហាញសារព្រមាន
    elseif ($access_check['status'] === 'warning') {
        $admin_subscription_warning = $access_check['message'];
    }

    initialize_sidebar_settings($mysqli, $current_admin_id); // Ensure settings exist
    $panel_title = get_setting($mysqli, $current_admin_id, 'panel_title', 'Admin Panel');
    $panel_logo_path = get_setting($mysqli, $current_admin_id, 'panel_logo_path', '');
    $show_title_with_logo = (bool)get_setting($mysqli, $current_admin_id, 'show_title_with_logo', '1');

    $default_footer = '&copy; ' . date("Y") . ' **Attendance Check-In System**. រៀបចំដោយ <a href="#" target="_blank">Your Company Name</a>. រក្សាសិទ្ធិគ្រប់យ៉ាង។';
    $footer_text = get_setting($mysqli, $current_admin_id, 'footer_text', $default_footer);

	if ($current_page == 'login' || $current_page == 'setup') {
		$current_page = 'dashboard';
        $current_action = 'dashboard';
	}

    // Check Access Permission for Non-Super Admins
    $admin_id_check = $_SESSION['admin_id'] ?? '';
    if (!$is_super_admin && !hasPageAccess($mysqli, $current_page, $current_action, $admin_id_check)) {
        // បើ Admin ធម្មតា ហើយទំព័រនេះមិនមានសិទ្ធិចូលប្រើ គឺបញ្ជូនទៅ Dashboard
        ob_end_clean();
        header("Location: admin_attendance.php?page=dashboard");
        exit;
    }

    // រាប់ PENDING REQUESTS
	$pending_requests_count = 0;
	if (hasPageAccess($mysqli, 'requests', 'requests', $_SESSION['admin_id'])) {
        if ($is_super_admin) {
            $count_query_sql = "SELECT COUNT(*) as pending_count FROM requests_logs WHERE request_status = 'Pending'";
            if ($stmt = $mysqli->prepare($count_query_sql)) {
                $stmt->execute();
                $result = $stmt->get_result();
                $row = $result ? $result->fetch_assoc() : null;
                $pending_requests_count = (int)($row['pending_count'] ?? 0);
                $stmt->close();
            }
        } else {
            // Filter by users that belong to this admin (more reliable than a created_by_admin_id on requests_logs)
            $count_query_sql = "SELECT COUNT(*) as pending_count
                                FROM requests_logs rl
                                JOIN users u ON rl.employee_id = u.employee_id
                                WHERE rl.request_status = 'Pending' AND u.created_by_admin_id = ?";
            if ($stmt = $mysqli->prepare($count_query_sql)) {
                $stmt->bind_param("s", $current_admin_id);
                $stmt->execute();
                $result = $stmt->get_result();
                $row = $result ? $result->fetch_assoc() : null;
                $pending_requests_count = (int)($row['pending_count'] ?? 0);
                $stmt->close();
            }
        }
	}


	// PHP Logic សម្រាប់ Dashboard Data Cards
	$today_date = date('Y-m-d');
    $total_users = 0;
	$total_admins = 0;
	$total_locations = 0;
	$active_sessions_count = 0;
	$today_good_count = 0;
	$today_late_count = 0;

    // Scope dashboard queries by admin_id
    $admin_scope_sql_users = " WHERE user_role = 'User' ";
    $admin_scope_sql_locations = "";
    if (!$is_super_admin) {
        $admin_scope_sql_users .= " AND (created_by_admin_id = '{$current_admin_id}') ";
        $admin_scope_sql_locations .= " WHERE created_by_admin_id = '{$current_admin_id}' ";
    }

    // Total Users
    if ($result = $mysqli->query("SELECT COUNT(*) as count FROM users" . $admin_scope_sql_users)) {
        $total_users = $result->fetch_assoc()['count'];
        $result->close();
    }
	// Total Admins (Super admin sees all non-super admins, normal admin sees none)
    if ($is_super_admin) {
        if ($result = $mysqli->query("SELECT COUNT(*) as count FROM users WHERE user_role = 'Admin' AND is_super_admin = FALSE")) {
            $total_admins = $result->fetch_assoc()['count'];
            $result->close();
        }
    } else {
        $total_admins = 0; // Normal admins don't manage other admins
    }
    // Total Locations
    if ($result = $mysqli->query("SELECT COUNT(*) as count FROM locations" . $admin_scope_sql_locations)) {
        $total_locations = $result->fetch_assoc()['count'];
        $result->close();
    }
    // Active Sessions (scoped for normal admin)
    if ($is_super_admin) {
        if ($result = $mysqli->query("SELECT COUNT(*) as count FROM active_tokens")) {
            $active_sessions_count = $result->fetch_assoc()['count'];
            $result->close();
        }
    } else {
        $sql = "SELECT COUNT(*) as count FROM active_tokens at JOIN users u ON at.employee_id = u.employee_id WHERE u.created_by_admin_id = ?";
        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $current_admin_id);
            $stmt->execute();
            $r = $stmt->get_result();
            if ($r) { $active_sessions_count = (int)($r->fetch_assoc()['count'] ?? 0); }
            $stmt->close();
        }
    }

	// Today Attendance Summary (Good and Late)
    $today_summary_sql = "
		SELECT
			SUM(CASE WHEN status = 'Good' THEN 1 ELSE 0 END) as good_count,
			SUM(CASE WHEN status = 'Late' THEN 1 ELSE 0 END) as late_count
		FROM checkin_logs
		WHERE DATE(log_datetime) = '{$today_date}'
	";
    if (!$is_super_admin) {
        $today_summary_sql .= " AND created_by_admin_id = '{$current_admin_id}'";
    }

	if ($result = $mysqli->query($today_summary_sql)) {
		$summary_data = $result->fetch_assoc();
		$today_good_count = (int)($summary_data['good_count'] ?? 0);
		$today_late_count = (int)($summary_data['late_count'] ?? 0);
		$result->close();
	}
}

// Flush output buffer បន្ទាប់ពី PHP Logic ទាំងអស់បានបញ្ចប់
ob_end_flush();
?>

<!DOCTYPE html>
<html lang="km">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<title>Admin Panel - Check In/Out</title>
    <!-- Performance: Resource Hints -->
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link rel="dns-prefetch" href="//fonts.googleapis.com">
    <link rel="dns-prefetch" href="//fonts.gstatic.com">
    <link rel="preconnect" href="https://cdnjs.cloudflare.com" crossorigin>
    <link rel="dns-prefetch" href="//cdnjs.cloudflare.com">
    <link rel="preconnect" href="https://code.jquery.com" crossorigin>
    <link rel="dns-prefetch" href="//code.jquery.com">
    <link rel="preconnect" href="https://i.ibb.co" crossorigin>
    <link rel="dns-prefetch" href="//i.ibb.co">
	<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" crossorigin="anonymous" referrerpolicy="no-referrer" />
	<link href="https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;600;700&display=swap" rel="stylesheet">
    <!-- Local Momo Trust Display font (Latin only) -->
	<script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
	<link rel="icon" href="https://i.ibb.co/kRJFYbC/Logo.png">

    <?php
    if (!$show_admin_pages) :
    ?>
    <style>
        @font-face {
            font-family: 'Momo Trust Display';
            src: url('assets/fonts/MomoTrustDisplay-Regular.woff2') format('woff2'),
                 url('assets/fonts/MomoTrustDisplay-Regular.woff') format('woff'),
                 url('assets/fonts/MomoTrustDisplay-Regular.ttf') format('truetype');
            font-weight: 400;
            font-style: normal;
            font-display: swap;
            unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC,
                           U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
        }
		:root {
			--primary-color: #3498db;
			--success-color: #2ecc71;
			--danger-color: #e74c3c;
			--warning-color: #f39c12;
			--dark-color: #2c3e50;
			--light-color: #ecf0f1;
			--text-color: #34495e;
		}
        body {
            /* Use Momo for English (Latin) and Kantumruy Pro for Khmer */
            font-family: 'Momo Trust Display', 'Kantumruy Pro', 'Work Sans', Arial, sans-serif;
            margin: 0;
            line-height: 1.6;
            font-weight: 400;
            background-color: #f0f4f7;
    /* Exclude Momo in form controls */
    input, textarea, select, button, .btn, .form-control { font-family: 'Kantumruy Pro', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif !important; }
            background-image: linear-gradient(to top, #cfd9df 0%, #e2ebf0 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: var(--text-color);
        }
        .login-wrapper {
            width: 100%;
            max-width: 450px;
            padding: 20px;
        }
        .login-box {
            width: 100%;
            padding: 40px 35px;
            background: #ffffff;
            border-radius: 12px;
            box-shadow: 0 10px 25px rgba(0, 0, 0, 0.08);
            border: 1px solid #e0e0e0;
            animation: slide-up 0.6s cubic-bezier(0.165, 0.84, 0.44, 1);
            margin: 0;
        }
        @keyframes slide-up {
            from { transform: translateY(30px); opacity: 0; }
            to { transform: translateY(0); opacity: 1; }
        }
        .login-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .login-header .icon {
            font-size: 3.5em;
            color: #ffffff;
            background: var(--primary-color);
            width: 80px;
            height: 80px;
            line-height: 80px;
            border-radius: 50%;
            margin: 0 auto 20px auto;
            box-shadow: 0 0 0 5px rgba(52, 152, 219, 0.2);
        }
        .login-header .login-logo-img {
            max-width: 250px;
            max-height: 80px;
            margin-bottom: 20px;
            object-fit: contain;
        }
        .login-header .icon.setup-icon {
            background: var(--success-color);
            box-shadow: 0 0 0 5px rgba(46, 204, 113, 0.2);
        }
        .login-box h2 {
            margin: 0;
            font-weight: 700;
            color: var(--dark-color);
            font-size: 1.8em;
        }
        .login-box .form-group { margin-bottom: 20px; }
        .login-box .form-group label {
            display: block; margin-bottom: 8px; font-weight: 600; font-size: 0.95em;
        }
        .login-box .form-group label i { margin-right: 8px; color: #7f8c8d; }
        .login-box .form-control {
            width: 100%; padding: 12px 16px; border: 1px solid #d1d9e0; border-radius: 8px;
            box-sizing: border-box; transition: all 0.3s ease; font-size: 1em; background-color: #f9fafb;
        }
        .login-box .form-control:focus {
            border-color: var(--primary-color); outline: none;
            box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.15); background-color: #fff;
        }
        .login-box .btn {
            width: 100%; padding: 14px 15px; border: none; border-radius: 8px;
            cursor: pointer; font-weight: 700; font-size: 1.05em;
            transition: all 0.3s ease; text-transform: uppercase; letter-spacing: 0.5px;
        }
        .login-box .btn:active { transform: translateY(1px); }
        .login-box .btn-primary {
            background-color: var(--primary-color); color: white;
            box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
        }
        .login-box .btn-primary:hover {
            background-color: var(--primary-color);
            filter: brightness(0.9);
            box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
        }
        .login-box .btn-success {
            background-color: var(--success-color); color: white;
            box-shadow: 0 4px 15px rgba(46, 204, 113, 0.3);
        }
        .login-box .btn-success:hover {
            background-color: #27ae60; box-shadow: 0 6px 20px rgba(46, 204, 113, 0.4);
        }
        .login-box .setup-note {
            text-align: center; margin-bottom: 20px; padding: 15px;
            border: 1px solid #f5c6cb; background-color: #f8d7da; border-radius: 6px;
            font-weight: 600; color: #721c24; font-size: 0.9em;
        }
        .login-box .alert {
            padding: 12px 15px; margin-bottom: 20px; border: 1px solid transparent;
            border-radius: 6px; font-weight: 600; font-size: 0.95em;
        }
        .alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
        .alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
    </style>
    <?php else: ?>
    <?php
    $dynamic_headers = [];
    if ($current_page == 'reports') {
        $fields_sql = "SELECT field_key, field_label FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC";
        if ($fields_stmt = $mysqli->prepare($fields_sql)) {
            $fields_stmt->bind_param("s", $current_admin_id);
            $fields_stmt->execute();
            $fields_result = $fields_stmt->get_result();
            while ($field_row = $fields_result->fetch_assoc()) {
                $dynamic_headers[$field_row['field_key']] = $field_row['field_label'];
            }
            $fields_stmt->close();
        }
    }
    ?>
	<style>
        :root {
            --primary-color: #3498db;
            --primary-color-hover: #2980b9;
        }
        body {
            /* Apply Momo for English (Latin), Khmer falls back to Kantumruy */
            font-family: 'Momo Trust Display', 'Kantumruy Pro', 'Work Sans', Arial, sans-serif;
			margin: 0; background-color: #f4f7f9; color: #34495e;
			line-height: 1.6; font-weight: 400;
		}
        /* Exclude Momo from inputs/buttons */
        input, textarea, select, button, .btn, .form-control { font-family: 'Kantumruy Pro', system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif !important; }
		h1, h2, h3, h4, .btn { font-weight: 600; }
		.admin-container { display: flex; min-height: 100vh; flex-direction: column; }
        .sidebar {
            width: 250px; background-color: #2c3e50; color: white;
            padding: 0; box-shadow: 4px 0 10px rgba(0, 0, 0, 0.15);
            position: fixed; top: 0; bottom: 0; z-index: 100;
            /* Use flex column so we can keep brand/footer fixed and let menu scroll */
            display: flex; flex-direction: column; overflow: hidden;
            transition: width 0.25s ease, transform 0.25s ease;
        }
		.sidebar h2 {
			text-align: center; margin-top: 0; margin-left: 15px; margin-right: 15px;
			margin-bottom: 30px; font-size: 1.6em; color: #ecf0f1;
			border-bottom: 2px solid #34495e; padding-bottom: 10px; height: 45px;
            display: flex; align-items: center; justify-content: center; gap: 10px;
		}
        .sidebar a {
            padding: 20px 15px; text-decoration: none; color: #bdc3c7;
            display: block; transition: background-color 0.3s, color 0.3s;
            font-size: 0.95em; font-weight: 500;
            box-shadow: 0 5px 5px rgba(0, 0, 0, 0.1);
            position: relative;
        }
		.sidebar a:hover { background-color: #34495e; color: white; }
		.sidebar a.active {
			background-color: var(--primary-color); color: white;  padding-left: 15px;
		}
		.sidebar a i { margin-right: 10px; width: 20px; text-align: center; }
        /* Scrollable menu area inside the sidebar */
        .sidebar-menu {
            flex: 1 1 auto; /* take remaining vertical space */
            overflow-y: auto; padding: 12px 8px 20px; -webkit-overflow-scrolling: touch;
        }
		.content-wrapper { display: flex; flex-grow: 1; }
		.main-content {
            margin-left: 250px; flex-grow: 1; padding: 30px;
            min-height: calc(100vh - 120px);
            transition: margin-left 0.25s ease;
		}
		.header {
			display: flex; justify-content: space-between; align-items: center;
			margin-bottom: 30px; padding-bottom: 15px; border-bottom: 2px solid #e9ecef;
		}
		.header h1 { margin: 0; color: var(--primary-color); }
		.logout-btn {
			background: #e74c3c; color: white; padding: 8px 15px;
			border-radius: 5px; text-decoration: none; transition: background-color 0.3s;
			font-weight: 600;
		}
		.logout-btn:hover { background-color: #c0392b; }
		.alert {
			padding: 15px; margin-bottom: 20px; border: 1px solid transparent;
			border-radius: 4px; font-weight: 600;
		}
		.alert-success { color: #155724; background-color: #d4edda; border-color: #c3e6cb; }
		.alert-danger { color: #721c24; background-color: #f8d7da; border-color: #f5c6cb; }
		.alert-info { color: #0c5460; background-color: #d1ecf1; border-color: #bee5eb; }
        .alert-warning { color: #856404; background-color: #fff3cd; border-color: #ffeeba; }
		.form-group { margin-bottom: 15px; }
		.form-group label { display: block; margin-bottom: 5px; font-weight: 600; }
		.form-control {
			width: 100%; padding: 10px; border: 1px solid #bdc3c7;
			border-radius: 4px; box-sizing: border-box; transition: border-color 0.3s;
		}
		.form-control:focus {
			border-color: var(--primary-color); outline: none; box-shadow: 0 0 5px rgba(52, 152, 219, 0.5);
		}
        input[type="color"].form-control {
            padding: 5px; /* Adjust padding for color input */
            height: 45px;
        }
		.btn {
			padding: 10px 15px; border: none; border-radius: 4px;
			cursor: pointer; font-weight: 600; transition: background-color 0.3s, transform 0.1s, filter 0.3s;
		}
		.btn:active { transform: translateY(1px); }
		.btn-primary { background-color: var(--primary-color); color: white; }
		.btn-primary:hover { background-color: var(--primary-color-hover); filter: brightness(0.9); }
		.btn-success { background-color: #2ecc71; color: white; }
        .btn-success:hover { background-color: #27ae60; }
		.btn-danger { background-color: #e74c3c; color: white; }
        .btn-danger:hover { background-color: #c0392b; }
		.table {
			width: 100%; border-collapse: separate; border-spacing: 0; margin-top: 20px;
			background-color: white; box-shadow: 0 4px 10px rgba(0, 0, 0, 0.05);
			border-radius: 8px; overflow: hidden;
		}
		.table th, .table td { padding: 12px 15px; border-bottom: 1px solid #ecf0f1; text-align: left; font-size: 0.9em; }
		.table th { background-color: #ecf0f1; font-weight: 700; color: #2c3e50; }
		.table tr:last-child td { border-bottom: none; }
		.table tr:nth-child(even) { background-color: #f9f9f9; }
        .table tr.submenu-setting-row td:first-child { padding-left: 40px; font-style: italic; position: relative; }
        .table tr.submenu-setting-row td:first-child::before { content: '↳'; position: absolute; left: 20px; color: #7f8c8d; }
        .status-good { color: white; background-color: #3498db; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
        .status-late { color: white; background-color: #e74c3c; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; }
        .status-badge { display: inline-block; padding: 5px 10px; border-radius: 15px; color: white; font-weight: 600; font-size: 0.85em; }
        .status-pending { background-color: #f39c12; }
        .status-approved { background-color: #2ecc71; }
        .status-rejected { background-color: #e74c3c; }

        /* Department navtabs styling */
        .department-navtabs {
            display: flex;
            justify-content: center;
            margin-bottom: 20px;
        }
        .department-navtabs .nav-tabs {
            border: none;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 16px;
            padding: 6px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            display: flex;
            gap: 4px;
        }
        .department-navtabs .nav-item {
            margin: 0;
        }
        .department-navtabs .nav-link {
            border: none !important;
            border-radius: 12px !important;
            padding: 12px 28px !important;
            font-weight: 600 !important;
            color: #6c757d !important;
            background: transparent !important;
            transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
            position: relative;
            overflow: hidden;
        }
        .department-navtabs .nav-link:hover {
            color: #495057 !important;
            background: rgba(255,255,255,0.8) !important;
            transform: translateY(-1px);
            box-shadow: 0 4px 8px rgba(0,0,0,0.15);
        }
        .department-navtabs .nav-link.active {
            color: #fff !important;
            background: linear-gradient(135deg, #3498db 0%, #2980b9 100%) !important;
            box-shadow: 0 4px 12px rgba(52,152,219,0.4) !important;
            transform: translateY(-2px);
        }
        .department-navtabs .nav-link i {
            margin-right: 8px;
            opacity: 0.8;
        }
        .department-navtabs .nav-link.active i {
            opacity: 1;
        }
    .reports-table-wrapper { background: #ffffff; border: 1px solid #e6e9ef; border-radius: 12px; box-shadow: 0 4px 10px rgba(0,0,0,0.04); overflow: auto; max-height: 65vh; content-visibility: auto; contain-intrinsic-size: 600px; }
        .reports-table-wrapper .table { margin: 0; box-shadow: none; border-radius: 0; min-width: 100%; }
        /* Prevent text wrapping in table cells for better specific dense data display */
        .reports-table-wrapper .table th,
        .reports-table-wrapper .table td { white-space: nowrap; vertical-align: middle; }
        /* Allow wrapping specifically for potentially long text columns */
        .reports-table-wrapper .table td.col-late_reason,
        .reports-table-wrapper .table td.col-noted { white-space: normal; min-width: 180px; max-width: 300px; }
        .reports-table-wrapper thead th { position: sticky; top: 0; z-index: 2; background: #ecf0f1; }
        .table tbody tr:hover { background-color: #f6fbff; }
        /* Highlight row when jumping from Late summary */
        .reports-table-wrapper .table tr.row-pulse {
            animation: rowPulse 1.4s ease-out 1;
            background-image: linear-gradient(90deg, #fff7f7, #fff);
        }
        /* Highlight selected attendance rows for manual counting */
        .reports-table-wrapper .table tr.attendance-selected td {
            background: #fff9e6 !important;
        }
        .reports-table-wrapper .table tr.attendance-selected {
            outline: 2px solid #f1c40f;
        }

        /* Fullscreen Reports Mode */
        body.fullscreen-mode .sidebar, body.fullscreen-mode .header, body.fullscreen-mode .footer {
            display: none !important;
        }
        body.fullscreen-mode .main-content {
            margin-left: 0 !important;
            padding: 20px !important;
            width: 100% !important;
            max-width: 100% !important;
            height: 100vh;
        }
        /* Exit Button */
        #fullscreenExitBtn {
            display: none;
            position: fixed;
            top: 20px;
            right: 20px;
            z-index: 9999;
            padding: 10px 20px;
            background: #e74c3c;
            color: white;
            border: none;
            border-radius: 8px;
            font-weight: 600;
            box-shadow: 0 4px 12px rgba(0,0,0,0.2);
            cursor: pointer;
            transition: all 0.2s ease;
            font-family: 'Kantumruy Pro', sans-serif;
        }
        #fullscreenExitBtn:hover {
            transform: translateY(-2px);
            box-shadow: 0 6px 16px rgba(0,0,0,0.3);
            background: #c0392b;
        }
        body.fullscreen-mode #fullscreenExitBtn {
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .attendance-selection-info {
            display:inline-block; background:#fdf2d6; color:#8d6d00; font-size:13px; padding:4px 10px; border-radius:14px; margin-left:12px; border:1px solid #f7e2a4;
        }
        @keyframes rowPulse { 0% { box-shadow: inset 0 0 0 0 rgba(231,76,60,0.0);} 50% { box-shadow: inset 0 0 0 3px rgba(231,76,60,0.35);} 100% { box-shadow: inset 0 0 0 0 rgba(231,76,60,0.0);} }

        /* Fullscreen fallback styling for reports table */
        #reportsTableWrapper.fullscreen-fallback {
            position: fixed; inset: 0; background: var(--surface); z-index: 2000; padding: 16px;
            max-height: none; height: 100vh; box-shadow: none; border-radius: 0; border: none;
        }
        #reportsTableWrapper.fullscreen-fallback .table { border-radius: 8px; }
        #reportsTableWrapper.fullscreen-fallback thead th { top: 0; }

        /* Native fullscreen styling (when wrapper enters real fullscreen) */
        #reportsTableWrapper:fullscreen {
            position: fixed; inset: 0; background: var(--surface); z-index: 2000; padding: 16px;
            width: 100vw; height: 100vh; max-height: none; overflow: auto; box-shadow: none; border-radius: 0; border: none;
        }
        #reportsTableWrapper:fullscreen .table { border-radius: 8px; }
        #reportsTableWrapper:fullscreen thead th { top: 0; }
        /* Safari/WebKit prefix */
        #reportsTableWrapper:-webkit-full-screen {
            position: fixed; inset: 0; background: var(--surface); z-index: 2000; padding: 16px;
            width: 100vw; height: 100vh; max-height: none; overflow: auto; box-shadow: none; border-radius: 0; border: none;
        }
        #reportsTableWrapper:-webkit-full-screen .table { border-radius: 8px; }
        #reportsTableWrapper:-webkit-full-screen thead th { top: 0; }

        /* Subscription banner styles */
        .subscription-banner {
            display: flex;
            gap: 16px;
            align-items: center;
            padding: 14px 18px;
            border-radius: 10px;
            background: linear-gradient(90deg, rgba(255,245,235,1) 0%, rgba(255,250,240,1) 100%);
            border: 1px solid rgba(243,156,18,0.15);
            box-shadow: 0 6px 18px rgba(243,156,18,0.06);
            color: #6b4b00;
            margin-bottom: 18px;
        }
        .subscription-banner .sub-icon {
            width: 56px; height: 56px; border-radius: 12px; display:flex; align-items:center; justify-content:center;
            background: linear-gradient(135deg, #f39c12 0%, #f1c40f 100%);
            color: white; font-size: 1.4rem; box-shadow: 0 6px 14px rgba(243,156,18,0.18);
            flex: 0 0 56px;
        }
        .subscription-banner .sub-content { flex: 1; min-width: 0; }
        .subscription-banner .sub-content .sub-title { font-weight: 700; color: #7a4b00; margin-bottom: 4px; font-size: 0.98rem; }
        .subscription-banner .sub-content .sub-desc { font-size: 0.92rem; color: #6b4b00; opacity: 0.95; }
        .subscription-banner .sub-cta { margin-left: 12px; }
        .subscription-banner .sub-cta .btn { padding: 8px 12px; border-radius: 8px; font-size: 0.9rem; }
        .subscription-banner small { display:block; color: rgba(107,75,0,0.8); margin-top:6px; font-weight:600; }

		hr { border: 0; border-top: 1px solid #ccc; margin: 40px 0; }
		.admin-reg-box { background: #ecf0f1; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); border: 1px solid #bdc3c7; }
		.modal { display: none; position: fixed; z-index: 1000; left: 0; top: 0; width: 100%; height: 100%; overflow: auto; background-color: rgba(0,0,0,0.8); }
		.modal-content { margin: 5% auto; display: block; width: 80%; max-width: 700px; text-align: left; background: white; padding: 0; border-radius: 8px; box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
        .modal-header { padding: 15px 25px; background-color: var(--primary-color); color: white; border-top-left-radius: 8px; border-top-right-radius: 8px; }
        .modal-header h3 { margin: 0; font-size: 1.5em; }
        .modal-body { padding: 25px; max-height: 70vh; overflow-y: auto; }
        .modal-footer { padding: 15px 25px; background-color: #f4f7f9; text-align: right; border-bottom-left-radius: 8px; border-bottom-right-radius: 8px; }
        .modal-footer .btn { margin-left: 10px; }
        #requestDetailModal .detail-grid { display: grid; grid-template-columns: 150px 1fr; gap: 10px; }
        #requestDetailModal .detail-grid > div { padding: 8px; }
        #requestDetailModal .detail-grid > div:nth-child(odd) { font-weight: 600; color: #7f8c8d; text-align: right; }
        .reason-box {
            margin-top: 20px; padding: 15px; background-color: #f9f9f9;
            border: 1px solid #ecf0f1; border-radius: 5px; white-space: pre-wrap;
            max-height: 200px; overflow-y: auto;
        }
		#qr-image-display, #edit-form-content { width: 100%; height: auto; max-width: 500px; margin: 10px auto; display: block; text-align: center; }
		.close { position: absolute; top: 15px; right: 35px; color: #f1f1f1; font-size: 40px; font-weight: bold; transition: 0.3s; cursor: pointer; }
		.close:hover, .close:focus { color: #bbb; text-decoration: none; }
		.download-btn-modal { margin-top: 15px; font-size: 1.1em; }
        /* Time rules editor - polished styles */
        #checkinRulesContainer, #checkoutRulesContainer { display: flex; flex-direction: column; gap: 10px; margin-top: 8px; }
        @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
        .time-rule-row {
            display: grid; grid-template-columns: auto 1fr auto 1fr auto 1.2fr 45px; align-items: center; gap: 12px;
            padding: 12px 15px; border: 1px solid #e2e8f0; border-radius: 12px; background: #ffffff;
            box-shadow: 0 2px 8px rgba(0,0,0,0.03); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
            margin-bottom: 8px;
        }
        .time-rule-row:hover { border-color: #3182ce; box-shadow: 0 4px 15px rgba(0,0,0,0.06); transform: translateY(-1px); background: #fff; }
        .time-rule-row[data-type="checkin"] { border-left: 6px solid #3182ce; }
        .time-rule-row[data-type="checkout"] { border-left: 6px solid #2f855a; }
        .time-rule-row label {
            font-size: 0.8rem; font-weight: 700; color: #4a5568;
            background: #f7fafc; padding: 5px 12px; border-radius: 20px;
            display: flex; align-items: center; gap: 5px; white-space: nowrap;
        }
        .time-rule-row[data-type="checkout"] label { background: #f0fff4; color: #276749; }
        .time-rule-row input[type="time"].form-control, .time-rule-row select.form-control {
            height: 42px; border-radius: 10px; border: 1px solid #e2e8f0;
            font-weight: 600; color: #2d3748; background: #fff;
        }
        .time-rule-row .remove-rule {
            height: 40px; width: 40px; border-radius: 10px; border: none;
            background: #fff5f5; color: #e53e3e; transition: all 0.2s; display: flex; align-items: center; justify-content: center;
        }
        .time-rule-row .remove-rule:hover { background: #feb2b2; color: #c53030; transform: scale(1.05); }
		details { border: 1px solid #bdc3c7; border-radius: 4px; padding: 0; background: white; margin-bottom: 10px; }
		summary { font-weight: 600; padding: 10px; cursor: pointer; list-style: none; position: relative; }
		summary::after { content: '▼'; position: absolute; right: 15px; font-size: 0.8em; transition: transform 0.2s; }
		details[open] summary::after { transform: rotate(180deg); }
		.checkbox-container { max-height: 200px; overflow-y: auto; border-top: 1px solid #bdc3c7; padding: 10px; }
		.checkbox-item { display: block; margin-bottom: 8px; cursor: pointer; }
		.checkbox-item input[type="checkbox"] { margin-right: 15px; transform: scale(1.2); cursor: pointer; }
		.checkbox-item label { cursor: pointer; font-weight: 400; }
		.pagination { display: flex; justify-content: center; padding: 20px 0; list-style: none; }
		.pagination li a {
			padding: 8px 16px; margin: 0 4px; border: 1px solid #ddd; color: var(--primary-color);
			text-decoration: none; border-radius: 4px; transition: background-color 0.3s, color 0.3s;
		}
		.pagination li a:hover { background-color: var(--primary-color); color: white; border-color: var(--primary-color); }
		.pagination li.active a { background-color: var(--primary-color); color: white; border-color: var(--primary-color); cursor: default; }
		.pagination li.disabled a { color: #aaa; cursor: not-allowed; border-color: #ddd; }
		.pagination li.disabled a:hover { background-color: transparent; color: #aaa; }
		.card-container { display: flex; flex-wrap: wrap; gap: 20px; margin-bottom: 30px; }
		.dashboard-card {
			flex: 1 1 200px; background: white; padding: 20px; border-radius: 8px;
			box-shadow: 0 4px 10px rgba(0, 0, 0, 0.08); display: flex; flex-direction: column;
			justify-content: space-between; align-items: flex-start; min-height: 120px;
			transition: transform 0.3s; border-left: 5px solid; position: relative; overflow: hidden;
		}
		.dashboard-card:hover { transform: translateY(-3px); box-shadow: 0 6px 15px rgba(0, 0, 0, 0.1); }
		.card-title { font-size: 1.1em; font-weight: 600; color: #7f8c8d; margin-bottom: 5px; z-index: 1; }
		.card-number { font-size: 2.5em; font-weight: 700; margin: 0; z-index: 1; }
		.card-icon { font-size: 3em; opacity: 0.2; position: absolute; right: 15px; bottom: 15px; line-height: 1; }
		.card-users { border-left-color: var(--primary-color); } .card-users .card-number { color: var(--primary-color); }
		.card-admins { border-left-color: #e67e22; } .card-admins .card-number { color: #e67e22; }
		.card-locations { border-left-color: #2ecc71; } .card-locations .card-number { color: #2ecc71; }
		.card-sessions { border-left-color: #e74c3c; } .card-sessions .card-number { color: #e74c3c; }
		.card-today-good { border-left-color: #2ecc71; } .card-today-good .card-number { color: #2ecc71; }
		.card-today-late { border-left-color: #f39c12; } .card-today-late .card-number { color: #f39c12; }
		.sidebar .sidebar-item { position: relative; }
		.sidebar .submenu-toggle { display: flex; justify-content: space-between; align-items: center; width: 100%; box-sizing: border-box; cursor: pointer; }
		.sidebar .submenu-arrow { transition: transform 0.3s ease; font-size: 0.8em; margin-right: 15px; }
		.sidebar .sidebar-item.open .submenu-arrow { transform: rotate(180deg); }
		.sidebar .submenu {
			list-style: none; padding: 0; margin: 0; background-color: #34495e;
			max-height: 0; overflow: hidden; transition: max-height 0.3s ease-out;
		}
		.sidebar .sidebar-item.open .submenu { max-height: 300px; /* Increased height */ }
		.sidebar .submenu li a { padding: 12px 20px 12px 45px; font-size: 0.9em; }
		.sidebar .submenu li a:hover, .sidebar .submenu li a.sub-active { background-color: #2c3e50; color: white;  }
		.sidebar .sidebar-item.active > .submenu-toggle { background-color: var(--primary-color); color: white;  padding-left: 15px; }
		.footer {
            margin-left: 250px; background-color: #34495e; color: #bdc3c7;
            padding: 15px 30px; text-align: center; font-size: 0.9em;
            border-top: 5px solid #2c3e50; margin-top: auto;
            transition: margin-left 0.25s ease;
		}
		.footer a { color: var(--primary-color); text-decoration: none; font-weight: 600; }
		.footer a:hover { text-decoration: underline; }
        .access-button-group { display: flex; gap: 5px; }
        .access-button-group .btn-sm { padding: 5px 10px; font-size: 0.8em; }
        .user-actions-group { display: inline-flex; align-items: center; gap: 6px; }
        .user-actions-group .btn-sm { padding: 5px 10px; font-size: 0.78em; line-height: 1.1; }
        .user-actions-group .btn-sm i { margin-right: 4px; }
        @media (max-width: 1100px) {
            .user-actions-group { flex-wrap: wrap; gap: 4px; }
        }
        /* Actions dropdown */
        .user-actions-dropdown { position: relative; display: inline-block; }
        .user-actions-dropdown .dropdown-toggle { min-width: 34px; padding: 4px 8px; }
        .user-actions-dropdown .dropdown-menu { display: none; position: absolute; right: 0; top: calc(100% + 4px); background: #fff; border: 1px solid #dfe6e9; border-radius: 8px; min-width: 160px; box-shadow: 0 8px 20px rgba(0,0,0,0.08); z-index: 1000; padding: 6px 0; }
        .user-actions-dropdown .dropdown-menu.open { display: block; }
        .user-actions-dropdown .dropdown-item { display: flex; align-items: center; gap: 8px; width: 100%; padding: 8px 12px; background: transparent; border: none; color: #2c3e50; text-align: left; cursor: pointer; font-size: 0.9em; }
        .user-actions-dropdown .dropdown-item:hover { background: #f5f7f9; }
        .user-actions-dropdown .dropdown-item i { width: 16px; text-align: center; }
        .subpage-access { margin-top: 10px; padding: 10px; border-left: 3px solid var(--primary-color); background: #ecf0f1; }
        .notification-badge {
            --badge-bg-1: #ff5a52;
            --badge-bg-2: #d63031;
            --badge-ring: rgba(255,255,255,0.95);
            color: #fff;
            background: linear-gradient(180deg, var(--badge-bg-1), var(--badge-bg-2));
            padding: 2px 8px;
            height: 20px;
            line-height: 16px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: 800;
            margin-left: 8px;
            vertical-align: middle;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            box-shadow: 0 4px 12px rgba(214,48,49,0.28);
            border: 2px solid var(--badge-ring);
            min-width: 22px;
            text-align: center;
            letter-spacing: 0.2px;
            transform: translateZ(0);
            transition: transform 0.15s ease, background 0.2s ease, box-shadow 0.2s ease;
        }
        .sidebar a.active .notification-badge, .sidebar a:hover .notification-badge {
            --badge-bg-1: #e74c3c;
            --badge-bg-2: #b3252a;
            box-shadow: 0 6px 16px rgba(183,28,28,0.32);
        }
        @keyframes badgePulse { 0% { transform: scale(1);} 35% { transform: scale(1.12);} 100% { transform: scale(1);} }
        .notification-badge.badge-pulse { animation: badgePulse 420ms ease-out; }
        .token-id-display { font-family: 'Courier New', monospace; background: #f8f9fa; padding: 2px 6px; border-radius: 3px; font-size: 0.8em; color: #495057; }
        .user-info-cell { line-height: 1.4; } .user-info-cell strong { color: #2c3e50; } .user-info-cell small { color: #6c757d; }
        .form-text { font-size: 0.875em; color: #6c757d; margin-top: 0.25rem; }
        .info-box { background: #f8f9fa; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); }
        .info-box ul { margin: 0; padding-left: 20px; } .info-box li { margin-bottom: 8px; }
        .tokens-page-section { margin-bottom: 40px; } .tokens-page-section:last-child { margin-bottom: 0; }
        .session-count-info {
            background: #e8f4fd; border: 1px solid #b8daff; border-radius: 6px;
            padding: 12px 16px; margin-bottom: 20px; color: #004085; font-weight: 600;
        }
        .session-count-info i { color: #0066cc; margin-right: 8px; }
        /* CSS for Toggle Switch */
        .switch { position: relative; display: inline-block; width: 50px; height: 24px; }
        .switch input { opacity: 0; width: 0; height: 0; }
        .slider { position: absolute; cursor: pointer; top: 0; left: 0; right: 0; bottom: 0; background-color: #ccc; transition: .4s; }
        .slider:before { position: absolute; content: ""; height: 18px; width: 18px; left: 3px; bottom: 3px; background-color: white; transition: .4s; }
        input:checked + .slider { background-color: var(--primary-color); }
        input:checked + .slider:before { transform: translateX(26px); }
        .slider.round { border-radius: 34px; }
        .slider.round:before { border-radius: 50%; }
        .form-section {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 25px;
        }
        .form-section h4 {
            margin-top: 0;
            margin-bottom: 15px;
            color: var(--primary-color);
            border-bottom: 1px solid #dee2e6;
            padding-bottom: 10px;
        }
        .form-section h4 i {
            margin-right: 8px;
        }

        /* --- Enhanced theme tokens and overrides --- */
        :root {
            --bg: #f4f7f9;
            --surface: #ffffff;
            --text: #34495e;
            --muted: #6c757d;
            --border: #e9ecef;
            --sidebar-bg: #2c3e50;
            --sidebar-accent: #34495e;
            --shadow-sm: 0 2px 6px rgba(0,0,0,0.06);
            --shadow-md: 0 6px 16px rgba(0,0,0,0.08);
        }
        html[data-theme="dark"] {
            --bg: #0f1722;
            --surface: #141c27;
            --text: #d1d7e0;
            --muted: #9aa6b2;
            --border: #233044;
            --sidebar-bg: #0b1320;
            --sidebar-accent: #142034;
            --primary-color: #4ea1ff;
            --primary-color-hover: #3a85d6;
            --shadow-sm: 0 2px 6px rgba(0,0,0,0.5);
            --shadow-md: 0 6px 16px rgba(0,0,0,0.5);
        }
        body { background-color: var(--bg); color: var(--text); }
        .form-control { background: var(--surface); color: var(--text); border-color: var(--border); border-radius: 8px; }
        .table { background-color: var(--surface); box-shadow: var(--shadow-sm); border: 1px solid var(--border); border-radius: 12px; }
        .table th, .table td { border-bottom-color: var(--border); }
        .table tr:nth-child(even) { background-color: color-mix(in srgb, var(--surface) 96%, var(--border)); }
        .footer { background-color: var(--sidebar-accent); border-top-color: var(--sidebar-bg); }
        .dashboard-card { background: var(--surface); box-shadow: var(--shadow-md); border-radius: 14px; }
        .card-title { color: var(--muted); }
        html[data-theme="dark"] .table th { background-color: #162232; }
        html[data-theme="dark"] .modal-content { background: var(--surface); color: var(--text); }
        html[data-theme="dark"] .admin-reg-box, html[data-theme="dark"] .form-section { background: #111a27; border-color: #223148; }

        /* Header utility buttons */
        .header .left-actions { display: flex; align-items: center; gap: 12px; }
        .header .right-actions { display: flex; align-items: center; gap: 10px; }
        .header h1 { font-size: 1.4rem; }
        .icon-btn { border: 1px solid var(--border); background: var(--surface); color: var(--text); border-radius: 8px; height: 36px; width: 36px; display: inline-flex; align-items: center; justify-content: center; cursor: pointer; box-shadow: var(--shadow-sm); }
        .icon-btn:hover { filter: brightness(0.98); border-color: var(--primary-color); }

        /* Collapsible sidebar (desktop) */
        body.sidebar-collapsed .sidebar { width: 74px; overflow: hidden; }
        body.sidebar-collapsed .main-content { margin-left: 74px; }
        body.sidebar-collapsed .footer { margin-left: 74px; }
        body.sidebar-collapsed .sidebar .brand .brand-title { display: none; }
        /* Brand/logo tidy layout in collapsed mode */
        body.sidebar-collapsed .sidebar .brand {
            margin: 10px auto 14px;
            padding: 8px 0;
            width: 100%;
            background: transparent;
            border: 0;
            box-shadow: none;
            justify-content: center;
        }
        body.sidebar-collapsed .sidebar .brand .logo-wrap {
            width: 48px; height: 48px;
            flex: 0 0 48px;
            background: transparent;
        }
        body.sidebar-collapsed .sidebar .brand .logo-wrap img {
            width: 100%; height: 100%; object-fit: contain;
        }
        body.sidebar-collapsed .sidebar a { padding-left: 12px; padding-right: 12px; }
        body.sidebar-collapsed .sidebar a i { margin-right: 0; width: auto; }
        body.sidebar-collapsed .sidebar > a { font-size: 0; }
        body.sidebar-collapsed .sidebar > a i { font-size: 1.1rem; }
        body.sidebar-collapsed .sidebar .submenu { display: none !important; }
    /* Hide submenu toggle text and chevrons when collapsed, keep icons visible */
    body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle { font-size: 0; justify-content: center; }
    body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle i { font-size: 1.1rem; }
    body.sidebar-collapsed .sidebar .submenu-arrow { display: none; }
    /* Hide submenu text but keep its icon visible */
    body.sidebar-collapsed .sidebar .submenu-toggle span { font-size: 0; }
    body.sidebar-collapsed .sidebar .submenu-toggle span i {
        font-size: 1.1rem !important;
        margin: 0;
        width: 24px; height: 24px;
        display: inline-flex; align-items: center; justify-content: center;
    }
    /* Ensure simple top-level links (no submenu) show icons only when collapsed */
    body.sidebar-collapsed .sidebar .sidebar-menu > a {
        font-size: 0; /* hide text label */
        padding-left: 12px; padding-right: 12px;
    }
    body.sidebar-collapsed .sidebar .sidebar-menu > a i {
        font-size: 1.15rem; /* keep icon visible */
        margin-right: 0;
        width: 24px; height: 24px;
        display: inline-flex; align-items: center; justify-content: center;
    }
    /* Remove left padding shifts on active items in collapsed mode */
    body.sidebar-collapsed .sidebar a.active { padding-left: 12px !important; }
    body.sidebar-collapsed .sidebar .sidebar-item.active > .submenu-toggle { padding-left: 12px !important; }
    body.sidebar-collapsed .sidebar .notification-badge {
        position: absolute; right: 14px; top: 10px;
        min-width: 10px; width: 10px; height: 10px; line-height: 10px; padding: 0;
        border-width: 0; font-size: 0; box-shadow: 0 0 0 2px rgba(255,255,255,0.85), 0 0 10px rgba(214,48,49,0.45);
    }
    /* Ensure icon-centering and consistent size in collapsed mode */
    body.sidebar-collapsed .sidebar > a,
    body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle {
        display: flex;
        align-items: center;
        justify-content: center;
        text-align: center;
    }
    body.sidebar-collapsed .sidebar a i {
        margin-right: 0;
        width: 24px;
        height: 24px;
        display: inline-flex;
        align-items: center;
        justify-content: center;
        line-height: 1;
    }



    /* Mobile sidebar overlay */
    .sidebar-overlay { position: fixed; inset: 0; background: rgba(0,0,0,0.35); z-index: 90; display: none; }
    .sidebar-overlay.show { display: block; }

        /* Responsive: sidebar as drawer on mobile */
        @media (max-width: 980px) {
            .sidebar { transform: translateX(-100%); transition: transform 0.25s ease; }
            .sidebar.open { transform: translateX(0); }
            .main-content { margin-left: 0; padding: 20px; }
            .footer { margin-left: 0; }
        }
        /* Prevent body scroll when mobile drawer is open */
        body.no-scroll { overflow: hidden; }

        /* Pretty checkboxes: unify look in tables and settings */
        #selectAllReports,
        .report-select,
        .reports-table-wrapper input[type="checkbox"],
        .checkbox-item input[type="checkbox"] {
            -webkit-appearance: none;
            -moz-appearance: none;
            appearance: none;
            width: 18px;
            height: 18px;
            border: 2px solid #d0d7de;
            border-radius: 6px;
            background: #ffffff;
            display: inline-grid;
            place-content: center;
            position: relative;
            cursor: pointer;
            transition: border-color .15s ease, background-color .15s ease, box-shadow .15s ease, transform .15s ease;
            vertical-align: middle;
            margin: 0; /* reset browser margins */
            accent-color: var(--primary-color);
        }
        /* Override any previous scaling */
        .checkbox-item input[type="checkbox"] { transform: none; }

        /* Hover/focus states */
        #selectAllReports:hover,
        .report-select:hover,
        .reports-table-wrapper input[type="checkbox"]:hover,
        .checkbox-item input[type="checkbox"]:hover { border-color: var(--primary-color); }

        #selectAllReports:focus,
        .report-select:focus,
        .reports-table-wrapper input[type="checkbox"]:focus,
        .checkbox-item input[type="checkbox"]:focus { outline: none; box-shadow: 0 0 0 3px rgba(52,152,219,0.25); }

        /* Checked state */
        #selectAllReports:checked,
        .report-select:checked,
        .reports-table-wrapper input[type="checkbox"]:checked,
        .checkbox-item input[type="checkbox"]:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        #selectAllReports:checked::after,
        .report-select:checked::after,
        .reports-table-wrapper input[type="checkbox"]:checked::after,
        .checkbox-item input[type="checkbox"]:checked::after {
            content: "";
            position: absolute;
            width: 5px; height: 9px;
            border: 2px solid #ffffff;
            border-top: 0; border-left: 0;
            transform: rotate(45deg);
            top: 1px; left: 5px;
        }

        /* Disabled look */
        #selectAllReports:disabled,
        .report-select:disabled,
        .reports-table-wrapper input[type="checkbox"]:disabled,
        .checkbox-item input[type="checkbox"]:disabled {
            cursor: not-allowed;
            background: #f6f8fa;
            border-color: #e5e9f0;
            opacity: 0.7;
        }
	</style>
	<style id="enhanced-group-style">
    /* Polished styles for group management & drag handles */
    .drag-handle, .drag-cell { user-select:none; }
    tr.group-header.dragging, tr.draggable-group.dragging { opacity: .55; }
    tr.group-header { transition: background-color .25s ease, box-shadow .25s ease; }
    tr.group-header:hover { background:#e8eef2 !important; box-shadow: inset 0 0 0 999px rgba(255,255,255,.35); }
    #groupsTableBody tr.draggable-group { transition: background-color .25s ease; }
    #groupsTableBody tr.draggable-group:hover { background:#f5f9fc; }
    #groupsTableBody tr.draggable-group.dragging { background:#d9ecf9; }
    #groupsTableBody td.drag-cell { font-size:18px; color:#5d6d7e; text-align:center; }
    #groupsTableBody td.drag-cell:hover { color:#2c3e50; }
    #saveGroupOrderBtn { position:relative; overflow:hidden; }
    #saveGroupOrderBtn:before { content:''; position:absolute; inset:0; background:linear-gradient(135deg, rgba(255,255,255,0.3), rgba(255,255,255,0)); opacity:0; transition:opacity .3s; }
    #saveGroupOrderBtn:hover:before { opacity:1; }
    .group-header .drag-handle { color:#5d6d7e; font-size:16px; display:inline-flex; align-items:center; justify-content:center; width:22px; height:22px; border-radius:6px; background:linear-gradient(145deg,#ffffff,#eef3f6); border:1px solid #d5dde3; box-shadow:0 1px 2px rgba(0,0,0,0.06); }
    .group-header .drag-handle:hover { background:#e2ebf1; color:#2c3e50; }
    .group-header.dragging .drag-handle { background:#3498db; color:#fff; border-color:#2980b9; }
    /* Smooth placeholder spacing when dragging */
    #usersTableBody tr.group-header.dragging td { background-image: repeating-linear-gradient(135deg,#d9ecf9 0 8px,#e8f3fb 8px 16px); }
    /* Compact toolbar row styling (screenshot area refinement) */
    .user-toolbar { display:flex; gap:18px; align-items:center; flex-wrap:wrap; background:#f7f9fb; padding:18px 22px; border:1px solid #e2e8ee; border-radius:14px; box-shadow:0 4px 14px rgba(0,0,0,0.045); margin-bottom:14px; }
    /* Improve vertical rhythm: labels & controls share consistent height and baseline */
    .user-toolbar .segment-label { font-weight:600; color:#2c3e50; display:flex; align-items:center; gap:6px; line-height:1.2; }
    .user-toolbar .segment-label label { display:inline-flex; align-items:center; height:44px; line-height:44px; padding:0 4px 0 0; font-size:15px; }
    .user-toolbar .segment-label label:not(:last-child){ margin-right:4px; }
    /* Fine tune Khmer label rendering using font smoothing & prevent wrap */
    .user-toolbar .segment-label label { -webkit-font-smoothing:antialiased; white-space:nowrap; }
    /* Ensure selects & inputs align perfectly with labels */
    .user-toolbar select.form-control, .user-toolbar input.form-control { display:inline-flex; align-items:center; }
    .user-toolbar select.form-control, .user-toolbar input.form-control { min-width:190px; background:#fff; border:1px solid #ced6dd; border-radius:10px; height:44px; padding:10px 16px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
    .user-toolbar button.btn { height:44px; border-radius:10px; font-weight:600; display:flex; align-items:center; gap:8px; letter-spacing:.35px; line-height:1; padding:0 18px; }
    .user-toolbar button.btn-sm { height:40px; padding:8px 16px; }
    .user-toolbar button.btn-primary { background:linear-gradient(135deg,#3498db,#2d82c2); border:none; }
    .user-toolbar button.btn-primary:hover { filter:brightness(.95); }
    .user-toolbar button.btn-danger { background:linear-gradient(135deg,#e74c3c,#c13b2d); border:none; }
    .user-toolbar button.btn-danger:hover { filter:brightness(.92); }
    .user-toolbar .status-badge-inline { background:#3498db; color:#fff; padding:4px 10px; border-radius:20px; font-size:12px; font-weight:600; letter-spacing:.3px; box-shadow:0 2px 6px rgba(52,152,219,.3); }
    /* Custom pretty checkboxes inside users table */
    #usersTableBody .user-row input[type=checkbox], #selectAllUsers {
        -webkit-appearance:none; -moz-appearance:none; appearance:none;
        width:18px; height:18px; border:2px solid #d0d7de; border-radius:6px; background:#fff;
        display:inline-grid; place-content:center; position:relative; cursor:pointer; transition:border-color .15s ease, background-color .15s ease, box-shadow .15s ease, transform .15s ease;
        vertical-align:middle; margin:0; accent-color: var(--primary-color);
    }
    #usersTableBody .user-row input[type=checkbox]:hover, #selectAllUsers:hover { border-color: var(--primary-color); }
    #usersTableBody .user-row input[type=checkbox]:focus, #selectAllUsers:focus { outline:none; box-shadow:0 0 0 3px rgba(52,152,219,0.25); }
    #usersTableBody .user-row input[type=checkbox]:checked, #selectAllUsers:checked { background-color: var(--primary-color); border-color: var(--primary-color); }
    #usersTableBody .user-row input[type=checkbox]:checked::after, #selectAllUsers:checked::after {
        content:""; position:absolute; width:5px; height:9px; border:2px solid #fff; border-top:0; border-left:0; transform:rotate(45deg); top:1px; left:5px;
    }
    #usersTableBody .user-row input[type=checkbox]:disabled, #selectAllUsers:disabled { cursor:not-allowed; background:#f6f8fa; border-color:#e5e9f0; opacity:.7; }
    /* Hover highlight for entire row when its checkbox is hovered */
    #usersTableBody .user-row input[type=checkbox]:hover { box-shadow:0 0 0 3px rgba(52,152,219,0.15); }
    #usersTableBody tr.user-row:hover { background:#f6fbff; }
    /* Slight scale animation when checking */
    #usersTableBody .user-row input[type=checkbox]:active { transform:scale(.85); }
    /* Disabled state refinement */
    .user-toolbar button:disabled { background:#dfe5ea !important; color:#7a8894 !important; cursor:not-allowed; box-shadow:none; }
    .user-toolbar select:disabled, .user-toolbar input:disabled { background:#f1f4f6; color:#9aa6b2; }
    /* Responsive tightening */
    @media (max-width: 880px){ .user-toolbar { padding:12px 12px; gap:10px; } .user-toolbar select.form-control, .user-toolbar input.form-control { min-width:140px; height:38px; } .user-toolbar button.btn { height:38px; } }
    @media (max-width: 640px){ .user-toolbar { flex-direction:column; align-items:stretch; } .user-toolbar select.form-control, .user-toolbar input.form-control { width:100%; } }
    /* Animation for save feedback */
    #saveGroupOrderBtn.saved::after { content:'✓'; position:absolute; right:8px; top:8px; background:#2ecc71; color:#fff; width:20px; height:20px; font-size:12px; display:flex; align-items:center; justify-content:center; border-radius:50%; box-shadow:0 2px 4px rgba(0,0,0,0.2); animation:popIn .4s ease; }
    @keyframes popIn { 0%{ transform:scale(.5); opacity:0;} 70%{ transform:scale(1.15); opacity:1;} 100%{ transform:scale(1); } }
    /* Improve checkbox vertical alignment in toolbar */
    .user-toolbar input[type=checkbox]{ position:relative; top:2px; }
    </style>
    <?php endif; ?>
</head>
<body class="<?php echo ($current_page == 'reports') ? 'fullscreen-mode' : ''; ?>">

<?php
// --- Remember-admin auto-login: If session not present but remember_admin cookie exists, try to restore admin session ---
if (empty($_SESSION['admin_logged_in']) && !empty($_COOKIE['remember_admin'])) {
    list($selector, $validator) = explode(':', $_COOKIE['remember_admin'], 2);
    if ($selector && $validator) {
        if ($stmt = $mysqli->prepare("SELECT * FROM auth_tokens WHERE selector = ? AND expires >= NOW()")) {
            $stmt->bind_param('s', $selector);
            $stmt->execute();
            $res = $stmt->get_result();
            $token = $res ? $res->fetch_assoc() : null;
            $stmt->close();

            if ($token) {
                if (hash_equals($token['hashed_validator'] ?? '', hash('sha256', $validator))) {
                    // Load admin user referenced by token
                    if ($u = $mysqli->prepare("SELECT employee_id, name, is_super_admin FROM users WHERE employee_id = ? AND user_role = 'Admin' LIMIT 1")) {
                        $u->bind_param('s', $token['user_id']);
                        $u->execute();
                        $ur = $u->get_result();
                        $user = $ur ? $ur->fetch_assoc() : null;
                        $u->close();

                        if ($user) {
                            $_SESSION['admin_logged_in'] = true;
                            $_SESSION['admin_id'] = $user['employee_id'];
                            $_SESSION['admin_name'] = $user['name'];
                            $_SESSION['is_super_admin'] = (bool)$user['is_super_admin'];
                            // log the remember-login event
                            log_user_event($mysqli, $user['employee_id'], 'admin_remember_login');
                        }
                    }
                }
            }
        }
    }
}

if (!$show_admin_pages) :
    if (isset($_GET['expired_msg'])) {
        $error = htmlspecialchars(urldecode($_GET['expired_msg']));
    }
?>
	<div class="login-wrapper">
		<div class="login-box">
			<?php if (!empty($success)): ?><div class="alert alert-success"><i class="fa-solid fa-circle-check"></i> <?php echo $success; ?></div><?php endif; ?>
			<?php if (!empty($error)): ?><div class="alert alert-danger"><i class="fa-solid fa-circle-exclamation"></i> <?php echo $error; ?></div><?php endif; ?>

			<?php if ($admin_count == 0): ?>
				<div class="login-header">
					<div class="icon setup-icon"><i class="fa-solid fa-gears"></i></div>
					<h2>Admin Panel Setup</h2>
				</div>
				<p class="setup-note"><i class="fa-solid fa-triangle-exclamation"></i> មិនទាន់មានគណនី Admin! សូមបង្កើតគណនីដំបូង ដែលនឹងក្លាយជា <strong>Super Admin</strong>។</p>
				<form id="initialAdminForm" method="POST" action="admin_attendance.php">
					<input type="hidden" name="initial_admin_register" value="1">
					<div class="form-group">
						<label for="admin_id"><i class="fa-solid fa-id-badge"></i> Admin ID</label>
						<input type="text" id="admin_id" name="admin_id" class="form-control" required placeholder="ឧ. admin01">
					</div>
					<div class="form-group">
						<label for="admin_name"><i class="fa-solid fa-user-tie"></i> ឈ្មោះ Admin</label>
						<input type="text" id="admin_name" name="admin_name" class="form-control" required placeholder="ឧ. សុខ ចាន់ថា">
					</div>
					<div class="form-group">
						<label for="admin_password"><i class="fa-solid fa-lock"></i> ពាក្យសម្ងាត់</label>
						<input type="password" id="admin_password" name="admin_password" class="form-control" required placeholder="••••••••••">
					</div>
					<button type="submit" class="btn btn-success" style="width: 100%; margin-top: 10px;">បង្កើត Super Admin</button>
				</form>

			<?php else: ?>
				<div class="login-header">
                    <?php if (!empty($login_page_logo_path) && file_exists($login_page_logo_path)): ?>
                        <img src="<?php echo htmlspecialchars($login_page_logo_path); ?>" alt="Logo" class="login-logo-img" loading="lazy" decoding="async">
                    <?php else: ?>
                        <div class="icon"><i class="<?php echo htmlspecialchars($login_page_icon_class); ?>"></i></div>
                    <?php endif; ?>
					<h2><?php echo htmlspecialchars($login_page_title); ?></h2>
				</div>
                <!-- Toggle tabs: Admin vs Sub User login -->
                <div style="display:flex; gap:8px; margin:10px 0 14px;">
                    <button type="button" id="tabAdminBtn" class="btn btn-primary" style="flex:1;">Admin Login</button>
                    <button type="button" id="tabSubBtn" class="btn btn-light" style="flex:1; border:1px solid #ddd;">Sub User Login</button>
                </div>

                <form id="adminLoginForm" method="POST" action="admin_attendance.php" onsubmit="return true;" style="display:block;">
                    <input type="hidden" name="admin_login" value="1">
                    <div class="form-group">
                        <label for="employee_id"><i class="fa-solid fa-id-badge"></i> Admin ID</label>
                        <input type="text" id="employee_id" name="employee_id" class="form-control" required placeholder="សូមបញ្ចូល Admin ID">
                    </div>
                    <div class="form-group">
                        <label for="password"><i class="fa-solid fa-lock"></i> ពាក្យសម្ងាត់</label>
                        <input type="password" id="password" name="password" class="form-control" required placeholder="សូមបញ្ចូលពាក្យសម្ងាត់">
                    </div>
                        <div class="form-group" style="margin-top:8px;">
                            <label style="display:flex; align-items:center; gap:8px; font-weight:600;">
                                <input type="checkbox" id="remember_admin" name="remember_admin" value="1" style="width:16px;height:16px;">
                                <span style="font-size:14px; color:#555;">ចងចាំ​ការ Login (Remember me)</span>
                            </label>
                        </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 10px;">ចូលប្រព័ន្ធ (Admin)</button>
                </form>

                <!-- Sub User Login: standard POST form (no AJAX) -->
                <form id="subUserLoginForm" method="POST" action="admin_attendance.php" onsubmit="return true;" style="margin-top:12px; display:none;">
                    <input type="hidden" name="sub_user_login" value="1">
                    <div class="form-group" style="padding:10px; border:1px dashed #ccc; border-radius:6px; background:#fafafa;">
                        <label style="display:flex; gap:6px; align-items:center; font-weight:600;"><i class="fa-solid fa-users-gear"></i> Sub User Login (Optional)</label>
                        <p style="font-size:12px; margin:4px 0 8px; color:#555;">អ្នកអាចចូលជា Sub User ដោយបំពេញតែ Sub ID និង Sub Password (Parent User ID មិនចាំបាច់ទេ)។ ប្រសិនបើ Sub ID មាន parent ច្រើន ត្រូវបញ្ជាក់ Parent ID ដើម្បីចៀសវាងភាពពិបាក (Ambiguous).</p>
                        <div class="form-group" style="margin-bottom:6px;">
                            <label for="parent_employee_id" style="font-size:12px;">Parent User ID (Optional)</label>
                            <input type="text" id="parent_employee_id" name="parent_employee_id" class="form-control" placeholder="ទុកទទេបើមិនចាំបាច់" autocomplete="off">
                        </div>
                        <div class="form-group" style="margin-bottom:6px; display:flex; align-items:center; gap:8px;">
                            <label style="display:flex; align-items:center; gap:8px; font-weight:600; margin:0;">
                                <input type="checkbox" id="vvc" name="vvc" value="1" style="width:16px;height:16px;">
                                <span style="font-size:13px; color:#555;">Vvc</span>
                            </label>
                        </div>
                        <div class="form-group" style="margin-bottom:6px; display:flex; gap:6px;">
                            <div style="flex:1;">
                                <label for="sub_id" style="font-size:12px;">Sub ID</label>
                                <input type="text" id="sub_id" name="sub_id" class="form-control" placeholder="Sub ID" autocomplete="off">
                            </div>
                            <div style="flex:1;">
                                <label for="sub_password" style="font-size:12px;">Sub Password</label>
                                <input type="password" id="sub_password" name="sub_password" class="form-control" placeholder="••••" autocomplete="new-password">
                            </div>
                        </div>
                        <button type="submit" class="btn btn-secondary btn-sm" style="width:100%;"><i class="fa-solid fa-share"></i> ចូលជា Sub User</button>
                    </div>
                </form>

                <script>
                (function(){
                    var tabAdminBtn = document.getElementById('tabAdminBtn');
                    var tabSubBtn = document.getElementById('tabSubBtn');
                    var adminForm = document.getElementById('adminLoginForm');
                    var subForm = document.getElementById('subUserLoginForm');
                    function showAdmin(){
                        adminForm.style.display = 'block';
                        subForm.style.display = 'none';
                        tabAdminBtn.className = 'btn btn-primary';
                        tabSubBtn.className = 'btn btn-light';
                        tabSubBtn.style.border = '1px solid #ddd';
                    }
                    function showSub(){
                        adminForm.style.display = 'none';
                        subForm.style.display = 'block';
                        tabAdminBtn.className = 'btn btn-light';
                        tabAdminBtn.style.border = '1px solid #ddd';
                        tabSubBtn.className = 'btn btn-primary';
                    }
                    tabAdminBtn && tabAdminBtn.addEventListener('click', showAdmin);
                    tabSubBtn && tabSubBtn.addEventListener('click', showSub);
                    // Default: show Admin form
                    showAdmin();
                    // One-time fill: when Vvc checkbox is checked, insert 'Vvc' into Parent User ID once
                    var vvcCheckbox = document.getElementById('vvc');
                    var parentInput = document.getElementById('parent_employee_id');
                    if (vvcCheckbox && parentInput) {
                        vvcCheckbox.addEventListener('change', function () {
                            try {
                                if (this.checked) {
                                    if (!parentInput.value) {
                                        parentInput.value = 'Vvc';
                                    }
                                    // disable checkbox to make it one-time
                                    this.disabled = true;
                                }
                            } catch (e) {
                                // ignore errors
                            }
                        });
                    }
                })();
                </script>
			<?php endif; ?>

		</div>
	</div>
<?php
exit; // Stop executing the rest of the page if not logged in
endif;
?>

<div class="admin-container">
    <div class="sidebar">
        <style>
        /* Small, self-contained styles for the sidebar brand area */
        .sidebar .brand {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            margin: 0 16px 18px;
            border-radius: 10px;
            background: linear-gradient(135deg, rgba(255,255,255,0.03), rgba(255,255,255,0.01));
            box-shadow: 0 8px 24px rgba(0,0,0,0.06);
            border: 1px solid rgba(255,255,255,0.03);
        }
        .sidebar .brand .logo-wrap {
            width: 64px;
            height: 64px;
            flex: 0 0 64px;
            border-radius: 50%;
            display: flex;
            align-items: center;
            justify-content: center;
            background: rgba(255,255,255,0.04);
            overflow: hidden;
        }
        .sidebar .brand .logo-wrap img {
            max-width: 100%;
            max-height: 100%;
            object-fit: contain;
            display: block;
        }
        .sidebar .brand .brand-title {
            color: #ecf0f1;
            font-weight: 700;
            font-size: 1rem;
            line-height: 1.1;
            text-transform: none;
        }
        .sidebar .brand .brand-title small {
            display: block;
            color: #bfc9d3;
            font-weight: 600;
            font-size: 0.78rem;
            margin-top: 4px;
        }
        /* Responsive adjustments */
        @media (max-width: 800px) {
            .sidebar .brand { padding: 12px; gap: 10px; margin: 8px 12px 12px; }
            .sidebar .brand .logo-wrap { width: 54px; height: 54px; }
            .sidebar .brand .brand-title { font-size: 0.95rem; }
        }
        /* Collapsed behavior: move sidebar-related collapsed rules here so styles are co-located */
        body.sidebar-collapsed .sidebar { width: 74px; overflow: hidden; }
        body.sidebar-collapsed .main-content { margin-left: 74px; }
        body.sidebar-collapsed .footer { margin-left: 74px; }
        body.sidebar-collapsed .sidebar .brand .brand-title { display: none; }
        body.sidebar-collapsed .sidebar .brand {
            margin: 10px auto 14px;
            padding: 8px 0;
            width: 100%;
            background: transparent;
            border: 0;
            box-shadow: none;
            justify-content: center;
        }
        body.sidebar-collapsed .sidebar .brand .logo-wrap {
            width: 48px; height: 48px;
            flex: 0 0 48px;
            background: transparent;
        }
        body.sidebar-collapsed .sidebar .brand .logo-wrap img {
            width: 100%; height: 100%; object-fit: contain;
        }
        body.sidebar-collapsed .sidebar a { padding-left: 12px; padding-right: 12px; }
        body.sidebar-collapsed .sidebar a i { margin-right: 0; width: auto; }
        body.sidebar-collapsed .sidebar > a { font-size: 0; }
        body.sidebar-collapsed .sidebar > a i { font-size: 1.1rem; }
        body.sidebar-collapsed .sidebar .submenu { display: none !important; }
        /* Hide submenu toggle text and chevrons when collapsed, keep icons visible */
        body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle { font-size: 0; justify-content: center; }
        body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle i { font-size: 1.1rem; }
        body.sidebar-collapsed .sidebar .submenu-arrow { display: none; }
        /* Hide submenu text but keep its icon visible */
        body.sidebar-collapsed .sidebar .submenu-toggle span { font-size: 0; }
        body.sidebar-collapsed .sidebar .submenu-toggle span i {
            font-size: 1.1rem !important;
            margin: 0;
            width: 24px; height: 24px;
            display: inline-flex; align-items: center; justify-content: center;
        }
        /* Ensure simple top-level links (no submenu) show icons only when collapsed */
        body.sidebar-collapsed .sidebar .sidebar-menu > a {
            font-size: 0; /* hide text label */
            padding-left: 12px; padding-right: 12px;
        }
        body.sidebar-collapsed .sidebar .sidebar-menu > a i {
            font-size: 1.15rem; /* keep icon visible */
            margin-right: 0;
            width: 24px; height: 24px;
            display: inline-flex; align-items: center; justify-content: center;
        }
        /* Remove left padding shifts on active items in collapsed mode */
        body.sidebar-collapsed .sidebar a.active { padding-left: 12px !important; }
        body.sidebar-collapsed .sidebar .sidebar-item.active > .submenu-toggle { padding-left: 12px !important; }
        body.sidebar-collapsed .sidebar .notification-badge {
            position: absolute; right: 14px; top: 10px;
            min-width: 10px; width: 10px; height: 10px; line-height: 10px; padding: 0;
            border-width: 0; font-size: 0; box-shadow: 0 0 0 2px rgba(255,255,255,0.85), 0 0 10px rgba(214,48,49,0.45);
        }
        /* Ensure icon-centering and consistent size in collapsed mode */
        body.sidebar-collapsed .sidebar > a,
        body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            text-align: center;
        }
        body.sidebar-collapsed .sidebar a i {
            margin-right: 0;
            width: 24px;
            height: 24px;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            line-height: 1;
        }

        /* Stronger collapse rules: ensure text labels are hidden in all cases while keeping icons visible */
        body.sidebar-collapsed .sidebar .sidebar-menu a,
        body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle,
        body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle span,
        body.sidebar-collapsed .sidebar .sidebar-menu > a span {
            font-size: 0 !important;
            line-height: 0 !important;
            white-space: nowrap !important;
        }

        /* Explicitly restore icon color and sizing so icons remain visible when labels are hidden */
        body.sidebar-collapsed .sidebar a i,
        body.sidebar-collapsed .sidebar .sidebar-item > .submenu-toggle i,
        body.sidebar-collapsed .sidebar .brand .logo-wrap i {
            font-size: 1.15rem !important;
            color: #bdc3c7 !important; /* visible neutral icon color */
            width: 24px !important;
            height: 24px !important;
            display: inline-flex !important;
            align-items: center !important;
            justify-content: center !important;
            line-height: 1 !important;
        }
        /* Make active icon stand out */
        body.sidebar-collapsed .sidebar a.active i,
        body.sidebar-collapsed .sidebar .sidebar-item.active > .submenu-toggle i {
            color: #ffffff !important;
        }
        /* ============================================================
           🎨 MODERN UI REDESIGN — Premium Admin Panel v2
           Overrides & enhances base styles without touching PHP/HTML
           ============================================================ */
        :root {
            --primary:        #3b82f6;
            --primary-dark:   #1d4ed8;
            --primary-light:  #eff6ff;
            --accent:         #6366f1;
            --success:        #10b981;
            --warning:        #f59e0b;
            --danger:         #ef4444;
            --sidebar-bg:     #0f172a;
            --sidebar-hover:  #1e293b;
            --sidebar-active: linear-gradient(135deg, #3b82f6 0%, #6366f1 100%);
            --surface:        #ffffff;
            --surface-alt:    #f8fafc;
            --border:         #e2e8f0;
            --text-primary:   #0f172a;
            --text-secondary: #64748b;
            --shadow-sm:      0 1px 3px rgba(0,0,0,0.08), 0 1px 2px rgba(0,0,0,0.05);
            --shadow-md:      0 4px 16px rgba(0,0,0,0.08), 0 2px 6px rgba(0,0,0,0.04);
            --shadow-lg:      0 20px 48px rgba(0,0,0,0.10), 0 6px 16px rgba(0,0,0,0.06);
            --radius-sm:      8px;
            --radius-md:      12px;
            --radius-lg:      16px;
            --sidebar-w:      256px;
            --header-h:       64px;
        }

        /* ── Body & Layout ── */
        body {
            background: linear-gradient(135deg, #f0f4ff 0%, #f8fafc 50%, #f0fdf4 100%) !important;
            background-attachment: fixed !important;
            color: var(--text-primary) !important;
        }

        .admin-container { display: flex; min-height: 100vh; flex-direction: column; }
        .content-wrapper { display: flex; flex-grow: 1; }

        /* ── Sidebar ── */
        .sidebar {
            width: var(--sidebar-w) !important;
            background: var(--sidebar-bg) !important;
            box-shadow: 4px 0 24px rgba(0,0,0,0.18) !important;
            border-right: none !important;
        }

        /* Sidebar brand area */
        .sidebar .brand {
            background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%) !important;
            border-bottom: 1px solid rgba(255,255,255,0.07) !important;
            padding: 16px 14px 14px !important;
            margin: 10px 12px 10px !important;
            border-radius: var(--radius-md) !important;
        }
        .sidebar .brand .logo-wrap {
            background: linear-gradient(135deg, var(--primary), var(--accent)) !important;
            box-shadow: 0 4px 14px rgba(99,102,241,0.40) !important;
        }
        .sidebar .brand .brand-title {
            color: #f1f5f9 !important;
            font-weight: 700 !important;
            letter-spacing: 0.3px;
        }
        .sidebar .brand .brand-title small {
            color: #94a3b8 !important;
        }

        /* Sidebar links */
        .sidebar a,
        .sidebar .submenu-toggle {
            color: #94a3b8 !important;
            padding: 11px 16px !important;
            font-size: 0.875rem !important;
            font-weight: 500 !important;
            border-radius: var(--radius-sm) !important;
            margin: 2px 8px !important;
            transition: all 0.2s ease !important;
            box-shadow: none !important;
        }
        .sidebar a:hover,
        .sidebar .submenu-toggle:hover {
            background: var(--sidebar-hover) !important;
            color: #f1f5f9 !important;
            transform: translateX(2px);
        }
        .sidebar a.active {
            background: var(--sidebar-active) !important;
            color: #fff !important;
            box-shadow: 0 4px 14px rgba(59,130,246,0.35) !important;
            font-weight: 600 !important;
        }
        .sidebar a i, .sidebar .submenu-toggle i {
            width: 20px !important;
            margin-right: 10px !important;
            font-size: 0.95rem !important;
            opacity: 0.85;
        }
        .sidebar a.active i { opacity: 1 !important; }

        /* Sidebar sub-menu */
        .sidebar .submenu { background: rgba(255,255,255,0.04) !important; border-radius: var(--radius-sm); margin: 0 8px; }
        .sidebar .submenu li a {
            padding: 9px 16px 9px 42px !important;
            font-size: 0.84rem !important;
            margin: 1px 0 !important;
            border-radius: 6px !important;
        }
        .sidebar .sidebar-item.active > .submenu-toggle {
            background: var(--sidebar-active) !important;
            color: #fff !important;
            box-shadow: 0 4px 14px rgba(59,130,246,0.30) !important;
        }

        /* SUPER ADMIN badge */
        .sidebar p[style*="f1c40f"] {
            background: linear-gradient(90deg,rgba(251,191,36,0.15),rgba(251,191,36,0.05)) !important;
            border: 1px solid rgba(251,191,36,0.25) !important;
            border-radius: var(--radius-sm) !important;
            margin: 0 12px 12px !important;
            padding: 8px !important;
            font-size: 0.75rem !important;
            letter-spacing: 1px;
        }

        /* ── Top Header bar ── */
        .header {
            background: rgba(255,255,255,0.85) !important;
            backdrop-filter: blur(12px) !important;
            -webkit-backdrop-filter: blur(12px) !important;
            border-bottom: 1px solid var(--border) !important;
            border-radius: var(--radius-lg) !important;
            padding: 14px 22px !important;
            margin-bottom: 24px !important;
            box-shadow: var(--shadow-sm) !important;
            position: sticky; top: 12px; z-index: 50;
        }
        .header h1 {
            font-size: 1.35rem !important;
            font-weight: 700 !important;
            color: var(--text-primary) !important;
            background: linear-gradient(135deg, var(--primary-dark), var(--accent));
            -webkit-background-clip: text !important;
            -webkit-text-fill-color: transparent !important;
            background-clip: text !important;
        }
        .logout-btn {
            background: linear-gradient(135deg, #ef4444, #dc2626) !important;
            border-radius: var(--radius-sm) !important;
            padding: 8px 18px !important;
            box-shadow: 0 3px 10px rgba(239,68,68,0.30) !important;
            font-size: 0.85rem !important;
            transition: all 0.2s ease !important;
        }
        .logout-btn:hover {
            transform: translateY(-1px) !important;
            box-shadow: 0 6px 16px rgba(239,68,68,0.40) !important;
        }

        /* ── Main Content ── */
        .main-content {
            margin-left: var(--sidebar-w) !important;
            padding: 20px 28px 40px !important;
            transition: margin-left 0.25s ease !important;
        }
        body.sidebar-collapsed .main-content { margin-left: 74px !important; }
        body.sidebar-collapsed .footer { margin-left: 74px !important; }

        /* ── Dashboard Cards ── */
        .card-container { gap: 18px !important; }
        .dashboard-card {
            border-radius: var(--radius-lg) !important;
            border: 1px solid var(--border) !important;
            border-left: none !important;
            box-shadow: var(--shadow-sm) !important;
            padding: 22px !important;
            background: var(--surface) !important;
            transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1) !important;
            position: relative; overflow: hidden;
        }
        .dashboard-card::before {
            content: '';
            position: absolute; top: 0; left: 0; right: 0; height: 3px;
            border-radius: var(--radius-lg) var(--radius-lg) 0 0;
        }
        .card-users::before   { background: linear-gradient(90deg, var(--primary), var(--accent)); }
        .card-admins::before  { background: linear-gradient(90deg, #f59e0b, #ef4444); }
        .card-locations::before { background: linear-gradient(90deg, var(--success), #06b6d4); }
        .card-sessions::before { background: linear-gradient(90deg, #ef4444, #ec4899); }
        .card-today-good::before { background: linear-gradient(90deg, var(--success), #10b981); }
        .card-today-late::before { background: linear-gradient(90deg, var(--warning), #ef4444); }

        .dashboard-card:hover {
            transform: translateY(-4px) !important;
            box-shadow: var(--shadow-lg) !important;
        }
        .card-title {
            font-size: 0.8rem !important;
            font-weight: 600 !important;
            color: var(--text-secondary) !important;
            text-transform: uppercase; letter-spacing: 0.5px;
        }
        .card-number { font-size: 2.4rem !important; font-weight: 800 !important; line-height: 1.1; }
        .card-icon {
            font-size: 2.6rem !important;
            opacity: 0.08 !important;
            right: 16px !important;
            bottom: 14px !important;
        }

        /* ── Buttons ── */
        .btn {
            border-radius: var(--radius-sm) !important;
            font-weight: 600 !important;
            font-size: 0.875rem !important;
            padding: 9px 18px !important;
            transition: all 0.2s ease !important;
            letter-spacing: 0.2px;
            border: none !important;
        }
        .btn:active { transform: scale(0.97) !important; }
        .btn-primary {
            background: linear-gradient(135deg, var(--primary), var(--primary-dark)) !important;
            box-shadow: 0 3px 10px rgba(59,130,246,0.30) !important;
        }
        .btn-primary:hover {
            background: linear-gradient(135deg, #2563eb, #1d4ed8) !important;
            box-shadow: 0 6px 16px rgba(59,130,246,0.40) !important;
            transform: translateY(-1px) !important; filter: none !important;
        }
        .btn-success {
            background: linear-gradient(135deg, #10b981, #059669) !important;
            box-shadow: 0 3px 10px rgba(16,185,129,0.28) !important;
        }
        .btn-success:hover {
            background: linear-gradient(135deg, #059669, #047857) !important;
            transform: translateY(-1px) !important;
        }
        .btn-danger {
            background: linear-gradient(135deg, #ef4444, #dc2626) !important;
            box-shadow: 0 3px 10px rgba(239,68,68,0.25) !important;
        }
        .btn-danger:hover {
            background: linear-gradient(135deg, #dc2626, #b91c1c) !important;
            transform: translateY(-1px) !important;
        }
        .btn-warning {
            background: linear-gradient(135deg, #f59e0b, #d97706) !important;
            color: #fff !important;
            box-shadow: 0 3px 10px rgba(245,158,11,0.26) !important;
        }
        .btn-secondary {
            background: linear-gradient(135deg, #64748b, #475569) !important;
            color: #fff !important;
        }
        .btn-sm { padding: 5px 12px !important; font-size: 0.8rem !important; border-radius: 6px !important; }

        /* ── Form Controls ── */
        .form-control {
            border: 1.5px solid var(--border) !important;
            border-radius: var(--radius-sm) !important;
            padding: 10px 14px !important;
            font-size: 0.88rem !important;
            background: var(--surface) !important;
            transition: border-color 0.2s ease, box-shadow 0.2s ease !important;
            color: var(--text-primary) !important;
        }
        .form-control:focus {
            border-color: var(--primary) !important;
            box-shadow: 0 0 0 3px rgba(59,130,246,0.15) !important;
            outline: none !important;
        }
        .form-group label { font-weight: 600 !important; font-size: 0.85rem !important; color: var(--text-secondary) !important; margin-bottom: 6px !important; }

        /* ── Tables ── */
        .table {
            background: var(--surface) !important;
            border-radius: var(--radius-lg) !important;
            box-shadow: var(--shadow-sm) !important;
            border: 1px solid var(--border) !important;
            overflow: hidden !important;
        }
        .table th {
            background: linear-gradient(135deg, #f8fafc, #f1f5f9) !important;
            color: var(--text-secondary) !important;
            font-size: 0.77rem !important;
            font-weight: 700 !important;
            text-transform: uppercase !important;
            letter-spacing: 0.5px !important;
            padding: 13px 16px !important;
            border-bottom: 2px solid var(--border) !important;
        }
        .table td {
            padding: 11px 16px !important;
            font-size: 0.875rem !important;
            border-bottom: 1px solid #f1f5f9 !important;
            vertical-align: middle !important;
            color: var(--text-primary) !important;
        }
        .table tr:last-child td { border-bottom: none !important; }
        .table tr:hover td { background: #f0f7ff !important; }
        .table tr:nth-child(even) { background: #fafbfc !important; }

        /* ── Status Badges ── */
        .status-good  { background: linear-gradient(135deg,#10b981,#059669) !important; border-radius: 20px !important; padding: 4px 12px !important; font-size: 0.75rem !important; }
        .status-late  { background: linear-gradient(135deg,#ef4444,#dc2626) !important; border-radius: 20px !important; padding: 4px 12px !important; font-size: 0.75rem !important; }
        .status-badge { border-radius: 20px !important; padding: 4px 12px !important; font-size: 0.78rem !important; }
        .status-pending  { background: linear-gradient(135deg,#f59e0b,#d97706) !important; }
        .status-approved { background: linear-gradient(135deg,#10b981,#059669) !important; }
        .status-rejected { background: linear-gradient(135deg,#ef4444,#dc2626) !important; }

        /* ── Alerts ── */
        .alert {
            border-radius: var(--radius-md) !important;
            border: none !important;
            padding: 14px 18px !important;
            display: flex; align-items: flex-start; gap: 12px;
            box-shadow: var(--shadow-sm) !important;
        }
        .alert-success { background: #ecfdf5 !important; color: #065f46 !important; border-left: 4px solid var(--success) !important; }
        .alert-danger  { background: #fef2f2 !important; color: #991b1b !important; border-left: 4px solid var(--danger) !important; }
        .alert-warning { background: #fffbeb !important; color: #92400e !important; border-left: 4px solid var(--warning) !important; }
        .alert-info    { background: #eff6ff !important; color: #1e40af !important; border-left: 4px solid var(--primary) !important; }

        /* ── Modal ── */
        .modal-content {
            border-radius: var(--radius-lg) !important;
            box-shadow: var(--shadow-lg) !important;
            border: none !important;
            overflow: hidden !important;
        }
        .modal-header {
            background: linear-gradient(135deg, var(--primary-dark), var(--accent)) !important;
            padding: 18px 24px !important;
            border-radius: 0 !important;
        }
        .modal-header h3 { font-size: 1.15rem !important; font-weight: 700 !important; }
        .modal-body { padding: 24px !important; background: var(--surface) !important; }
        .modal-footer { background: var(--surface-alt) !important; padding: 16px 24px !important; border-top: 1px solid var(--border) !important; }

        /* ── Footer ── */
        .footer {
            margin-left: var(--sidebar-w) !important;
            background: var(--sidebar-bg) !important;
            color: #64748b !important;
            font-size: 0.82rem !important;
            border-top: 1px solid rgba(255,255,255,0.06) !important;
            padding: 18px 30px !important;
            transition: margin-left 0.25s ease !important;
        }
        .footer a { color: var(--primary) !important; }

        /* ── Pagination ── */
        .pagination li a {
            border-radius: var(--radius-sm) !important;
            border: 1.5px solid var(--border) !important;
            font-weight: 600 !important;
            font-size: 0.85rem !important;
        }
        .pagination li a:hover { background: var(--primary) !important; color: #fff !important; border-color: var(--primary) !important; }
        .pagination li.active a { background: linear-gradient(135deg,var(--primary),var(--accent)) !important; border-color: var(--primary) !important; }

        /* ── Hamburger (Mobile) button ── */
        #sidebarToggleBtn {
            display: none;
            position: fixed; top: 14px; left: 14px; z-index: 600;
            background: var(--sidebar-bg);
            color: #fff; border: none; border-radius: var(--radius-sm);
            width: 42px; height: 42px; cursor: pointer;
            align-items: center; justify-content: center;
            box-shadow: var(--shadow-md);
            transition: background 0.2s ease;
        }
        #sidebarToggleBtn:hover { background: var(--sidebar-hover); }
        #sidebarOverlay {
            display: none; position: fixed; inset: 0; z-index: 450;
            background: rgba(0,0,0,0.45); backdrop-filter: blur(2px);
        }

        /* ── Responsive Breakpoints ── */
        @media (max-width: 1024px) {
            :root { --sidebar-w: 220px; }
            .main-content  { padding: 16px 18px 36px !important; }
            .card-number   { font-size: 2rem !important; }
        }

        @media (max-width: 768px) {
            /* Mobile: sidebar slides out off-screen */
            .sidebar {
                transform: translateX(-100%);
                position: fixed !important; z-index: 500 !important;
                width: 260px !important;
                transition: transform 0.28s cubic-bezier(0.4,0,0.2,1) !important;
            }
            .sidebar.mobile-open { transform: translateX(0) !important; }
            #sidebarOverlay.active { display: block !important; }
            #sidebarToggleBtn { display: flex !important; }

            .main-content {
                margin-left: 0 !important;
                padding: 70px 14px 32px !important;
            }
            .footer { margin-left: 0 !important; }

            .header {
                border-radius: var(--radius-md) !important;
                padding: 12px 14px !important;
                position: static !important;
                margin-bottom: 18px !important;
            }
            .header h1 { font-size: 1.1rem !important; }

            .card-container {
                display: grid !important;
                grid-template-columns: 1fr 1fr !important;
                gap: 12px !important;
            }
            .dashboard-card { min-height: 100px !important; padding: 16px !important; }
            .card-number { font-size: 1.7rem !important; }

            .table th, .table td { padding: 9px 10px !important; font-size: 0.8rem !important; }

            /* Stack header buttons on small screens */
            .header { flex-wrap: wrap; gap: 8px; }
        }

        @media (max-width: 480px) {
            .card-container { grid-template-columns: 1fr !important; }
            .btn { padding: 8px 14px !important; font-size: 0.82rem !important; }
            .main-content { padding: 68px 10px 28px !important; }
        }

        /* ── Scrollbar Styling ── */
        .sidebar-menu::-webkit-scrollbar { width: 4px; }
        .sidebar-menu::-webkit-scrollbar-track { background: transparent; }
        .sidebar-menu::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.15); border-radius: 10px; }

        /* ── Smooth page links ── */
        .sidebar a, .btn { transition: all 0.2s ease !important; }

        </style>

        <!-- Hamburger + Mobile Sidebar Toggle Script -->
        <div id="sidebarToggleBtn" role="button" aria-label="Toggle Menu" onclick="toggleMobileSidebar()">
            <i class="fa-solid fa-bars" style="font-size:1.1rem"></i>
        </div>
        <div id="sidebarOverlay" onclick="toggleMobileSidebar()"></div>
        <script>
        function toggleMobileSidebar() {
            const sidebar  = document.querySelector('.sidebar');
            const overlay  = document.getElementById('sidebarOverlay');
            const btn      = document.getElementById('sidebarToggleBtn');
            const isOpen   = sidebar && sidebar.classList.contains('mobile-open');
            if (sidebar) sidebar.classList.toggle('mobile-open', !isOpen);
            if (overlay) overlay.classList.toggle('active', !isOpen);
            if (btn) btn.innerHTML = isOpen
                ? '<i class="fa-solid fa-bars"   style="font-size:1.1rem"></i>'
                : '<i class="fa-solid fa-xmark"  style="font-size:1.1rem"></i>';
        }
        // Close sidebar when a nav link is clicked (mobile)
        document.addEventListener('DOMContentLoaded', function(){
            document.querySelectorAll('.sidebar a').forEach(function(a){
                a.addEventListener('click', function(){
                    if (window.innerWidth <= 768) toggleMobileSidebar();
                });
            });
        });
        </script>



        <div class="brand" role="banner" aria-label="Admin Panel Brand">
            <div class="logo-wrap" aria-hidden="true">
                <?php if (!empty($panel_logo_path) && file_exists($panel_logo_path)): ?>
                    <img src="<?php echo htmlspecialchars($panel_logo_path); ?>" alt="Logo" loading="lazy" decoding="async" fetchpriority="low">
                <?php else: ?>
                    <i class="fa-solid fa-building-shield" style="color: rgba(255,255,255,0.9); font-size: 22px;"></i>
                <?php endif; ?>
            </div>
            <div class="brand-title">
                <?php if ($show_title_with_logo || empty($panel_logo_path)): ?>
                    <?php echo htmlspecialchars($panel_title); ?>
                    <small>Admin Panel</small>
                <?php endif; ?>
            </div>
        </div>

		<?php if ($is_super_admin): ?>
			<p style="text-align: center; color: #f1c40f; font-weight: 700; border-bottom: 1px solid #f1c40f; padding-bottom: 10px; margin: 0 20px 20px;">
				<i class="fa-solid fa-star"></i> SUPER ADMIN <i class="fa-solid fa-star"></i>
			</p>
		<?php endif; ?>

		<?php
		$admin_id_check = $_SESSION['admin_id'] ?? '';
		$is_users_page = ($current_page == 'users');
		$is_reports_page = ($current_page == 'reports');
		$is_requests_page = ($current_page == 'requests');
		$is_notifications_page = ($current_page == 'notifications');
		$is_locations_page = ($current_page == 'locations');
		$is_categories_page = ($current_page == 'categories');
        $is_tokens_page = ($current_page == 'tokens');
        $is_settings_page = ($current_page == 'settings');

        $can_see_users = false; foreach($admin_pages_list['users'] as $action => $name) { if (hasPageAccess($mysqli, 'users', $action, $admin_id_check)) { $can_see_users = true; break; } }
        $can_see_reports = hasPageAccess($mysqli, 'reports', 'reports', $admin_id_check);
        $can_see_requests = hasPageAccess($mysqli, 'requests', 'requests', $admin_id_check);
        $can_see_notifications = hasPageAccess($mysqli, 'notifications', 'send_notifications', $admin_id_check);
        $can_see_locations = false; foreach($admin_pages_list['locations'] as $action => $name) { if (hasPageAccess($mysqli, 'locations', $action, $admin_id_check)) { $can_see_locations = true; break; } }
        $can_see_categories = hasPageAccess($mysqli, 'categories', 'categories', $admin_id_check);
        $can_see_tokens = false; foreach($admin_pages_list['tokens'] as $action => $name) { if (hasPageAccess($mysqli, 'tokens', $action, $admin_id_check)) { $can_see_tokens = true; break; } }

        $can_see_settings = false;
        foreach($admin_pages_list['settings'] as $action => $name) {
            if (hasPageAccess($mysqli, 'settings', $action, $admin_id_check)) {
                $can_see_settings = true;
                break;
            }
        }

        $sidebar_menu_items = [];
        $menu_stmt = $mysqli->prepare("SELECT menu_key, menu_text, icon_class FROM sidebar_settings WHERE admin_id = ? ORDER BY menu_order ASC");
        $menu_stmt->bind_param("s", $current_admin_id);
        $menu_stmt->execute();
        $menu_result = $menu_stmt->get_result();
        if($menu_result){
            while($row = $menu_result->fetch_assoc()){
                $sidebar_menu_items[$row['menu_key']] = $row;
            }
        }
		$menu_stmt->close();

        $submenu_texts = [];
        $submenu_stmt = $mysqli->prepare("SELECT menu_key, action_key, submenu_text FROM submenu_settings WHERE admin_id = ?");
        $submenu_stmt->bind_param("s", $current_admin_id);
        $submenu_stmt->execute();
        $submenu_result = $submenu_stmt->get_result();
        if ($submenu_result) {
            while ($row = $submenu_result->fetch_assoc()) {
                $submenu_texts[$row['menu_key']][$row['action_key']] = $row['submenu_text'];
            }
        }
        $submenu_stmt->close();
        ?>

        <div class="sidebar-menu" role="navigation" aria-label="Main menu">

        <?php
        foreach($sidebar_menu_items as $key => $menu):
            $page_key = $key;
            $menu_text = htmlspecialchars($menu['menu_text']);
            $menu_icon = htmlspecialchars($menu['icon_class']);
            if (isSidebarHidden($mysqli, $current_admin_id, $page_key)) { continue; }

            switch($page_key):
                case 'dashboard': ?>
                    <a href="?page=dashboard" class="<?php echo ($current_page == 'dashboard') ? 'active' : ''; ?>"><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></a>
                    <?php break;

                case 'users':
                    if ($can_see_users):
                        $user_action = $_GET['action'] ?? 'list_users'; ?>
                        <div class="sidebar-item has-submenu <?php echo $is_users_page ? 'active open' : ''; ?>">
                            <a href="?page=users&action=list_users" class="submenu-toggle <?php echo $is_users_page ? 'active' : ''; ?>">
                                <span><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></span>
                                <i class="fa-solid fa-chevron-down submenu-arrow"></i>
                            </a>
                            <ul class="submenu">
                                <?php if (hasPageAccess($mysqli, 'users', 'list_users', $admin_id_check)): ?>
                                <li><a href="?page=users&action=list_users" class="<?php echo ($is_users_page && in_array($user_action, ['list_users', 'edit_rules', 'edit_admin_access', 'edit_admin_subscription'])) ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['users']['list_users'] ?? 'បញ្ជីអ្នកប្រើប្រាស់'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check)): ?>
                                <li><a href="?page=users&action=create_user" class="<?php echo ($is_users_page && $user_action == 'create_user') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['users']['create_user'] ?? 'បង្កើតអ្នកប្រើប្រាស់'); ?></a></li>
                                <?php endif; ?>
                                <?php if ($is_super_admin && hasPageAccess($mysqli, 'users', 'create_admin', $admin_id_check)): ?>
                                <li><a href="?page=users&action=create_admin" class="<?php echo ($is_users_page && $user_action == 'create_admin') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['users']['create_admin'] ?? 'បង្កើតគណនី Admin'); ?></a></li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    <?php endif;
                    break;

                case 'reports':
                    if ($can_see_reports && !isSidebarHidden($mysqli, $current_admin_id, 'reports')):
                        $reports_active = ($current_page == 'reports'); ?>
                        <div class="sidebar-item has-submenu <?php echo $reports_active ? 'active open' : ''; ?>">
                            <a href="?page=reports" class="<?php echo $reports_active ? 'active' : ''; ?>"><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></a>
                            <ul class="submenu">
                                <li><a href="#" onclick="openColumnVisibility(); return false;">Column Visibility</a></li>
                            </ul>
                        </div>
                    <?php endif;
                    break;

                case 'requests':
                    if ($can_see_requests && !isSidebarHidden($mysqli, $current_admin_id, 'requests')): ?>
                        <a href="?page=requests" class="<?php echo ($current_page == 'requests') ? 'active' : ''; ?>">
                            <i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?>
                            <?php if ($pending_requests_count > 0): ?>
                                <span class="notification-badge"><?php echo $pending_requests_count; ?></span>
                            <?php endif; ?>
                        </a>
                    <?php endif;
                    break;

                case 'notifications':
                    if (hasPageAccess($mysqli, 'notifications', 'send_notifications', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'notifications')): ?>
                        <a href="?page=notifications" class="<?php echo ($current_page == 'notifications') ? 'active' : ''; ?>"><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></a>
                    <?php endif;
                    break;

                case 'locations':
                    if ($can_see_locations):
                        $location_action = $_GET['action'] ?? 'list_locations'; ?>
                        <div class="sidebar-item has-submenu <?php echo $is_locations_page ? 'active open' : ''; ?>">
                            <a href="?page=locations&action=list_locations" class="submenu-toggle <?php echo $is_locations_page ? 'active' : ''; ?>">
                                <span><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></span>
                                <i class="fa-solid fa-chevron-down submenu-arrow"></i>
                            </a>
                            <ul class="submenu">
                                <?php if (hasPageAccess($mysqli, 'locations', 'create_location', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'locations', 'create_location')): ?>
                                <li><a href="?page=locations&action=create_location" class="<?php echo ($is_locations_page && $location_action == 'create_location') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['locations']['create_location'] ?? 'បង្កើតទីតាំងថ្មី'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'locations', 'assign_location', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'locations', 'assign_location')): ?>
                                <li><a href="?page=locations&action=assign_location" class="<?php echo ($is_locations_page && $location_action == 'assign_location') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['locations']['assign_location'] ?? 'កំណត់ទីតាំងបុគ្គលិក'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'locations', 'list_locations', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'locations', 'list_locations')): ?>
                                <li><a href="?page=locations&action=list_locations" class="<?php echo ($is_locations_page && $location_action == 'list_locations') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['locations']['list_locations'] ?? 'បញ្ជីទីតាំង & ការកំណត់'); ?></a></li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    <?php endif;
                    break;

                case 'categories':
                    if ($can_see_categories && !isSidebarHidden($mysqli, $current_admin_id, 'categories')): ?>
                        <a href="?page=categories" class="<?php echo ($current_page == 'categories') ? 'active' : ''; ?>"><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></a>
                    <?php endif;
                    break;

                case 'tokens':
                    if ($can_see_tokens && !isSidebarHidden($mysqli, $current_admin_id, 'tokens')):
                        $token_action = $_GET['action'] ?? 'global_settings'; ?>
                        <div class="sidebar-item has-submenu <?php echo $is_tokens_page ? 'active open' : ''; ?>">
                            <a href="?page=tokens&action=global_settings" class="submenu-toggle <?php echo $is_tokens_page ? 'active' : ''; ?>">
                                <span><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></span>
                                <i class="fa-solid fa-chevron-down submenu-arrow"></i>
                            </a>
                            <ul class="submenu">
                                <?php if (hasPageAccess($mysqli, 'tokens', 'global_settings', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'tokens', 'global_settings')): ?>
                                <li><a href="?page=tokens&action=global_settings" class="<?php echo ($is_tokens_page && $token_action == 'global_settings') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['tokens']['global_settings'] ?? 'Global Token Settings'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'tokens', 'active_sessions', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'tokens', 'active_sessions')): ?>
                                <li><a href="?page=tokens&action=active_sessions" class="<?php echo ($is_tokens_page && $token_action == 'active_sessions') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['tokens']['active_sessions'] ?? 'បញ្ជី Session សកម្ម'); ?></a></li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    <?php endif;
                    break;

                case 'settings':
                    if ($can_see_settings && !isSidebarHidden($mysqli, $current_admin_id, 'settings')):
                        $settings_action = $_GET['action'] ?? 'panel_settings'; ?>
                        <div class="sidebar-item has-submenu <?php echo $is_settings_page ? 'active open' : ''; ?>">
                            <a href="?page=settings&action=panel_settings" class="submenu-toggle <?php echo $is_settings_page ? 'active' : ''; ?>">
                                <span><i class="<?php echo $menu_icon; ?>"></i> <?php echo $menu_text; ?></span>
                                <i class="fa-solid fa-chevron-down submenu-arrow"></i>
                            </a>
                            <ul class="submenu">
                                <?php if (hasPageAccess($mysqli, 'settings', 'panel_settings', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'settings', 'panel_settings')): ?>
                                <li><a href="?page=settings&action=panel_settings" class="<?php echo ($is_settings_page && $settings_action == 'panel_settings') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['settings']['panel_settings'] ?? 'ការកំណត់ Panel'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'settings', 'menu_settings', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'settings', 'menu_settings')): ?>
                                <li><a href="?page=settings&action=menu_settings" class="<?php echo ($is_settings_page && $settings_action == 'menu_settings') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['settings']['menu_settings'] ?? 'ការកំណត់ Menu'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'settings', 'login_page_settings', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'settings', 'login_page_settings')): ?>
                                <li><a href="?page=settings&action=login_page_settings" class="<?php echo ($is_settings_page && $settings_action == 'login_page_settings') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['settings']['login_page_settings'] ?? 'ការកំណត់ Login Page'); ?></a></li>
                                <?php endif; ?>

                                <?php if (hasPageAccess($mysqli, 'settings', 'manage_user_fields', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'settings', 'manage_user_fields')): ?>
                                <li><a href="?page=settings&action=manage_user_fields" class="<?php echo ($is_settings_page && $settings_action == 'manage_user_fields') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['settings']['manage_user_fields'] ?? 'គ្រប់គ្រង Fields អ្នកប្រើប្រាស់'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'settings', 'manage_request_fields', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'settings', 'manage_request_fields')): ?>
                                <li><a href="?page=settings&action=manage_request_fields" class="<?php echo ($is_settings_page && $settings_action == 'manage_request_fields') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['settings']['manage_request_fields'] ?? 'គ្រប់គ្រង Fields សំណើរ'); ?></a></li>
                                <?php endif; ?>
                                <?php if (hasPageAccess($mysqli, 'settings', 'manage_app_scan', $admin_id_check) && !isSidebarHidden($mysqli, $current_admin_id, 'settings', 'manage_app_scan')): ?>
                                <li><a href="?page=settings&action=manage_app_scan" class="<?php echo ($is_settings_page && $settings_action == 'manage_app_scan') ? 'sub-active' : ''; ?>"><?php echo htmlspecialchars($submenu_texts['settings']['manage_app_scan'] ?? 'គ្រប់គ្រង App Scan'); ?></a></li>
                                <?php endif; ?>
                            </ul>
                        </div>
                    <?php endif;
                    break;

            endswitch;
    endforeach;
    ?>

        </div>

        <a href="?logout=true" class="logout-link"><i class="fa-solid fa-right-from-bracket"></i> ចេញពីប្រព័ន្ធ</a>
	</div>

        <div class="sidebar-overlay" id="sidebarOverlay"></div>
    <div class="content-wrapper">
        <div class="main-content">
            <div class="header">
                <div class="left-actions">
                    <button id="toggleSidebar" class="icon-btn" title="Toggle sidebar"><i class="fa-solid fa-bars"></i></button>
                    <h1><?php echo strtoupper(str_replace('_', ' ', $current_page)); ?></h1>
                </div>
                <div class="right-actions">
                    <button id="toggleTheme" class="icon-btn" title="Toggle theme"><i class="fa-solid fa-moon"></i></button>
                    <a href="?logout=true" class="logout-btn"><i class="fa-solid fa-arrow-right-from-bracket"></i> ចេញ (<?php echo $_SESSION['admin_name']; ?>)</a>
                </div>
            </div>

            <div id="ajax-message-container">
            <?php if (!empty($admin_subscription_warning)): ?>
                <div class="subscription-banner" role="status" aria-live="polite">
                    <div class="sub-icon" aria-hidden="true"><i class="fa-solid fa-calendar-exclamation"></i></div>
                    <div class="sub-content">
                        <div class="sub-title">សេចក្តីជូនដំណឹង Subscription</div>
                        <div class="sub-desc"><?php echo $admin_subscription_warning; ?></div>
                    </div>
                    <div class="sub-cta"><a href="?page=users&action=list_users" class="btn btn-danger btn-sm">ពិនិត្យ Subscription</a></div>
                </div>
            <?php endif; ?>
            </div>

            <?php if ($current_page == 'dashboard'): ?>
                <h2><i class="fa-solid fa-chart-line"></i> ទិន្នន័យសង្ខេបប្រចាំថ្ងៃ: <?php echo date('d/m/Y'); ?></h2>


                <div class="card-container">
                    <div class="dashboard-card card-today-good">
                        <span class="card-title">វត្តមានទាន់ពេល (Good) ថ្ងៃនេះ</span>
                        <p class="card-number"><?php echo number_format($today_good_count); ?></p>
                        <i class="fa-solid fa-circle-check card-icon" style="color: #2ecc71;"></i>
                    </div>

                    <div class="dashboard-card card-today-late">
                        <span class="card-title">វត្តមានយឺត (Late) ថ្ងៃនេះ</span>
                        <p class="card-number"><?php echo number_format($today_late_count); ?></p>
                        <i class="fa-solid fa-hourglass-end card-icon" style="color: #f39c12;"></i>
                    </div>

                    <div class="dashboard-card card-users">
                        <span class="card-title">បុគ្គលិកសរុប (User)</span>
                        <p class="card-number"><?php echo number_format($total_users); ?></p>
                        <i class="fa-solid fa-users card-icon"></i>
                    </div>

                    <div class="dashboard-card card-locations">
                        <span class="card-title">ទីតាំង Check-In សរុប</span>
                        <p class="card-number"><?php echo number_format($total_locations); ?></p>
                        <i class="fa-solid fa-map-marker-alt card-icon" style="color: #2ecc71;"></i>
                    </div>

                    <div class="dashboard-card card-sessions">
                        <span class="card-title">Session កំពុងប្រើប្រាស់</span>
                        <p class="card-number"><?php echo number_format($active_sessions_count); ?></p>
                        <i class="fa-solid fa-key card-icon" style="color: #e74c3c;"></i>
                    </div>

                    <?php if ($is_super_admin): ?>
                    <div class="dashboard-card card-admins">
                        <span class="card-title">គណនី Admin សរុប</span>
                        <p class="card-number"><?php echo number_format($total_admins); ?></p>
                        <i class="fa-solid fa-user-shield card-icon" style="color: #e67e22;"></i>
                    </div>
                    <?php endif; ?>
                </div>

            <?php endif; ?>

           <?php if ($current_page == 'reports' && ($current_action == 'reports' || $current_action == '')): ?>
    <?php
    $dates_query_sql = "SELECT DISTINCT DATE(cl.log_datetime) as attendance_date
                        FROM checkin_logs cl
                        JOIN users u ON cl.employee_id = u.employee_id" .
                       ($is_super_admin ? "" : " WHERE u.created_by_admin_id = ?") .
                       " ORDER BY attendance_date DESC";

    $dates_stmt = $mysqli->prepare($dates_query_sql);
    if (!$is_super_admin) { $dates_stmt->bind_param("s", $current_admin_id); }
    $dates_stmt->execute();
    $dates_result = $dates_stmt->get_result();
    $available_dates = [];
    if ($dates_result) {
        while ($row = $dates_result->fetch_assoc()) {
            $available_dates[] = $row['attendance_date'];
        }
    }
    $dates_stmt->close();

    $filter_date = $_GET['filter_date'] ?? ($available_dates[0] ?? date('Y-m-d'));
    $filter_status = $_GET['filter_status'] ?? 'All';
    $filter_department = $_GET['filter_department'] ?? 'department';

    // Late employees summary for selected date
    $late_summary = [];
    $start_dt = $filter_date . ' 00:00:00';
    $end_dt   = $filter_date . ' 23:59:59';

    $late_sql = "SELECT u.employee_id, u.name, COUNT(*) as late_count
                 FROM checkin_logs cl
                 JOIN users u ON cl.employee_id = u.employee_id
                 WHERE cl.log_datetime BETWEEN ? AND ? AND cl.status = 'Late'";
    $late_types = 'ss';
    $late_params = [$start_dt, $end_dt];
    if (!$is_super_admin) {
        $late_sql .= " AND u.created_by_admin_id = ?";
        $late_types .= 's';
        $late_params[] = $current_admin_id;
    }
    $late_sql .= " GROUP BY u.employee_id, u.name ORDER BY u.name ASC";

    if ($stmt_late = $mysqli->prepare($late_sql)) {
        $stmt_late->bind_param($late_types, ...$late_params);
        $stmt_late->execute();
        $res_late = $stmt_late->get_result();
        if ($res_late) { $late_summary = $res_late->fetch_all(MYSQLI_ASSOC); }
        $stmt_late->close();
    }

    // Optimization: Batch fetch entries and rules for all late users to avoid N+1 queries
    if (!empty($late_summary)) {
        $late_user_ids = array_column($late_summary, 'employee_id');
        $placeholders = implode(',', array_fill(0, count($late_user_ids), '?'));

        // 1. Fetch ALL late entries for these users on this date
        $all_entries = [];
        $entries_sql = "SELECT cl.employee_id, cl.location_name, cl.log_datetime
                        FROM checkin_logs cl
                        JOIN users u ON cl.employee_id = u.employee_id
                        WHERE cl.employee_id IN ($placeholders)
                        AND cl.log_datetime BETWEEN ? AND ?
                        AND cl.status = 'Late'" . ($is_super_admin ? "" : " AND u.created_by_admin_id = ?") . "
                        ORDER BY cl.log_datetime ASC";

        if ($stmt_e = $mysqli->prepare($entries_sql)) {
            $e_types = str_repeat('s', count($late_user_ids)) . 'ss';
            $e_params = array_merge($late_user_ids, [$start_dt, $end_dt]);
            if (!$is_super_admin) {
                $e_types .= 's';
                $e_params[] = $current_admin_id;
            }
            $stmt_e->bind_param($e_types, ...$e_params);
            $stmt_e->execute();
            $res_e = $stmt_e->get_result();
            if ($res_e) {
                while ($row_e = $res_e->fetch_assoc()) {
                    $all_entries[$row_e['employee_id']][] = $row_e;
                }
            }
            $stmt_e->close();
        }

        // 2. Fetch ALL checkin rules for these users
        $all_rules = [];
        $rules_sql = "SELECT employee_id, type, start_time, end_time, status
                      FROM attendance_rules
                      WHERE employee_id IN ($placeholders) AND type = 'checkin'";
        if ($stmt_r = $mysqli->prepare($rules_sql)) {
            $stmt_r->bind_param(str_repeat('s', count($late_user_ids)), ...$late_user_ids);
            $stmt_r->execute();
            $res_r = $stmt_r->get_result();
            if ($res_r) {
                while ($row_r = $res_r->fetch_assoc()) {
                    $all_rules[$row_r['employee_id']][] = $row_r;
                }
            }
            $stmt_r->close();
        }

        // 3. Map entries and calculate late minutes
        foreach ($late_summary as &$usr) {
            $eid = $usr['employee_id'];
            $usr['entries'] = $all_entries[$eid] ?? [];

            if (!empty($usr['entries'])) {
                foreach ($usr['entries'] as &$entry) {
                    $entry['late_minutes'] = null;
                    $log_hms = date('H:i:s', strtotime($entry['log_datetime']));

                    // Pivot logic matching scan.php
                    $pivot_time = '';
                    $u_rules = $all_rules[$eid] ?? [];

                    // Try to find Good end_time <= log_time
                    $best_good = null;
                    foreach ($u_rules as $r) {
                        if ($r['status'] === 'Good' && $r['end_time'] <= $log_hms) {
                            if ($best_good === null || $r['end_time'] > $best_good['end_time']) {
                                $best_good = $r;
                            }
                        }
                    }
                    if ($best_good) {
                        $pivot_time = $best_good['end_time'];
                    } else {
                        // Fallback to earliest start time
                        $earliest = null;
                        foreach ($u_rules as $r) {
                            if ($earliest === null || $r['start_time'] < $earliest['start_time']) {
                                $earliest = $r;
                            }
                        }
                        if ($earliest) $pivot_time = $earliest['start_time'];
                    }

                    if ($pivot_time !== '') {
                        if (preg_match('/^\d{1,2}:\d{2}$/', $pivot_time)) { $pivot_time .= ':00'; }
                        $base_dt = date('Y-m-d', strtotime($entry['log_datetime'])) . ' ' . $pivot_time;
                        $late_secs = strtotime($entry['log_datetime']) - strtotime($base_dt);
                        if ($late_secs > 0) {
                            // FIX: Use ceil for accuracy
                            $mins = (int)ceil($late_secs / 60);
                            $entry['late_minutes'] = $mins;
                        }
                    }
                }
                unset($entry);
            }
        }
        unset($usr);
    }

    $records_per_page = 200;
    $current_p_page = isset($_GET['p']) ? (int)$_GET['p'] : 1;
    if ($current_p_page < 1) { $current_p_page = 1; }
    $offset = ($current_p_page - 1) * $records_per_page;

    $count_sql = "SELECT COUNT(*) as total
                  FROM checkin_logs cl
                  JOIN users u ON cl.employee_id = u.employee_id
                  WHERE cl.log_datetime BETWEEN ? AND ?";
    $count_params = [$start_dt, $end_dt];
    $count_types = "ss";

    if ($filter_status !== 'All') {
        $count_sql .= " AND cl.status = ?";
        $count_params[] = $filter_status;
        $count_types .= "s";
    }
    if ($filter_department === 'worker') {
        $count_sql .= " AND JSON_EXTRACT(u.custom_data, '$.department') = ?";
        $count_params[] = 'Worker';
        $count_types .= "s";
    } elseif ($filter_department === 'department') {
        $count_sql .= " AND (JSON_EXTRACT(u.custom_data, '$.department') != ? OR JSON_EXTRACT(u.custom_data, '$.department') IS NULL)";
        $count_params[] = 'Worker';
        $count_types .= "s";
    }
    if (!$is_super_admin) {
        $count_sql .= " AND u.created_by_admin_id = ?";
        $count_params[] = $current_admin_id;
        $count_types .= "s";
    }

    $total_records = 0;
    if ($stmt_count = $mysqli->prepare($count_sql)) {
        if(!empty($count_types)) $stmt_count->bind_param($count_types, ...$count_params);
        $stmt_count->execute();
        $count_result = $stmt_count->get_result();
        if ($count_result) $total_records = $count_result->fetch_assoc()['total'];
        $stmt_count->close();
    }

    $total_pages = ceil($total_records / $records_per_page);

    // [កូដដែលបានកែសម្រួល] เพิ่ม cl.custom_fields_data
    $sql = "SELECT cl.*, u.custom_data, cl.custom_fields_data
            FROM checkin_logs cl
            LEFT JOIN users u ON cl.employee_id = u.employee_id
            WHERE cl.log_datetime BETWEEN ? AND ?";
    $params = [$start_dt, $end_dt];
    $types = "ss";

    if ($filter_status !== 'All') {
        $sql .= " AND cl.status = ?";
        $params[] = $filter_status;
        $types .= "s";
    }
    // Apply department filter to paginated query (same logic as count/export)
    if ($filter_department === 'worker') {
        $sql .= " AND JSON_EXTRACT(u.custom_data, '$.department') = ?";
        $params[] = 'Worker';
        $types .= "s";
    } elseif ($filter_department === 'department') {
        $sql .= " AND (JSON_EXTRACT(u.custom_data, '$.department') != ? OR JSON_EXTRACT(u.custom_data, '$.department') IS NULL)";
        $params[] = 'Worker';
        $types .= "s";
    }
    if (!$is_super_admin) {
        $sql .= " AND u.created_by_admin_id = ?";
        $params[] = $current_admin_id;
        $types .= "s";
    }

    $sql .= " ORDER BY u.name ASC, cl.log_datetime ASC LIMIT ? OFFSET ?";
    $params[] = $records_per_page;
    $params[] = $offset;
    $types .= "ii";

    $report_data = [];
    if ($stmt = $mysqli->prepare($sql)) {
        if(!empty($types)) $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $report_data = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    }

    // [កូដដែលបានកែសម្រួល] เพิ่ม cl.custom_fields_data
    $export_sql = "SELECT cl.*, u.custom_data, cl.custom_fields_data, u.name as name
                   FROM checkin_logs cl
                   LEFT JOIN users u ON cl.employee_id = u.employee_id
                   WHERE cl.log_datetime BETWEEN ? AND ?";
    $export_params = [$start_dt, $end_dt];
    $export_types = "ss";

    if ($filter_status !== 'All') {
        $export_sql .= " AND cl.status = ?";
        $export_params[] = $filter_status;
        $export_types .= "s";
    }
    if ($filter_department === 'worker') {
        $export_sql .= " AND JSON_EXTRACT(u.custom_data, '$.department') = ?";
        $export_params[] = 'Worker';
        $export_types .= "s";
    } elseif ($filter_department === 'department') {
        $export_sql .= " AND (JSON_EXTRACT(u.custom_data, '$.department') != ? OR JSON_EXTRACT(u.custom_data, '$.department') IS NULL)";
        $export_params[] = 'Worker';
        $export_types .= "s";
    }
    if (!$is_super_admin) {
        $export_sql .= " AND u.created_by_admin_id = ?";
        $export_params[] = $current_admin_id;
        $export_types .= "s";
    }
    $export_sql .= " ORDER BY u.name ASC, cl.log_datetime ASC";

    $export_data = [];
    if ($stmt_exp = $mysqli->prepare($export_sql)) {
        if(!empty($export_types)) $stmt_exp->bind_param($export_types, ...$export_params);
        $stmt_exp->execute();
        $export_data = $stmt_exp->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt_exp->close();
    }
    ?>
     <h2><i class="fa-solid fa-chart-line"></i> របាយការណ៍វត្តមានបុគ្គលិក</h2>

    <!-- Date/status filter moved below department tabs -->

    <div style="margin-top: 24px; background: linear-gradient(135deg, #fff5f5 0%, #fef2f2 100%); border: 1px solid #fecaca; border-radius: 16px; box-shadow: 0 8px 24px rgba(239,68,68,0.12); padding: 24px; position: relative; overflow: hidden;">
        <!-- Decorative background element -->
        <div style="position: absolute; top: 0; right: 0; width: 120px; height: 120px; background: radial-gradient(circle, rgba(239,68,68,0.08) 0%, transparent 70%); border-radius: 50%; transform: translate(40px, -40px);"></div>

        <div style="position: relative; z-index: 1;">
            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px; flex-wrap: wrap; gap: 12px;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="width: 48px; height: 48px; background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); border-radius: 12px; display: flex; align-items: center; justify-content: center; box-shadow: 0 4px 12px rgba(239,68,68,0.3);">
                        <i class="fa-solid fa-triangle-exclamation" style="color: white; font-size: 20px;"></i>
                    </div>
                    <div>
                        <h3 style="margin: 0 0 4px 0; color: #dc2626; font-size: 1.4em; font-weight: 700;">បុគ្គលិកដែលយឺត (Late)</h3>
                        <p style="margin: 0; color: #7f1d1d; font-size: 0.95em; opacity: 0.9;">សម្រាប់ថ្ងៃ <?php echo date('d/m/Y', strtotime($filter_date)); ?></p>
                    </div>
                </div>

                <?php if (!empty($late_summary)): ?>
                <div style="display: flex; align-items: center; gap: 12px;">
                    <div style="background: linear-gradient(135deg, #dc2626 0%, #b91c1c 100%); color: white; padding: 8px 16px; border-radius: 20px; font-weight: 700; font-size: 0.9em; box-shadow: 0 4px 12px rgba(220,38,38,0.3); display: flex; align-items: center; gap: 8px;">
                        <i class="fa-solid fa-user-clock"></i>
                        <span><?php echo count($late_summary); ?> នាក់</span>
                    </div>
                </div>
                <?php endif; ?>
            </div>

            <?php if (empty($late_summary)): ?>
                <div style="text-align: center; padding: 40px 20px;">
                    <div style="width: 80px; height: 80px; background: linear-gradient(135deg, #10b981 0%, #059669 100%); border-radius: 50%; display: inline-flex; align-items: center; justify-content: center; margin-bottom: 16px; box-shadow: 0 8px 24px rgba(16,185,129,0.3);">
                        <i class="fa-solid fa-circle-check" style="color: white; font-size: 32px;"></i>
                    </div>
                    <h4 style="margin: 0 0 8px 0; color: #059669; font-weight: 600;">អស្ចារ្យ! 🎉</h4>
                    <p style="margin: 0; color: #6b7280; font-size: 1em;">មិនមានបុគ្គលិកយឺតនៅថ្ងៃនេះទេ។</p>
                </div>
            <?php else: ?>
                <div style="margin-bottom: 16px;">
                    <p style="margin: 0; color: #7f1d1d; font-size: 0.95em; display: flex; align-items: center; gap: 8px;">
                        <i class="fa-solid fa-info-circle"></i>
                        បញ្ជីខាងក្រោមជាបុគ្គលិកដែលមានស្ថានភាព Late ក្នុងថ្ងៃបានជ្រើសរើស
                    </p>
                </div>

                <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 16px;">
                    <?php foreach ($late_summary as $late):
                        $emp_safe = preg_replace('/[^a-zA-Z0-9_-]/', '_', $late['employee_id']);
                        $total_late_minutes = 0;
                        if (!empty($late['entries'])) {
                            foreach ($late['entries'] as $entry) {
                                if (isset($entry['late_minutes'])) {
                                    $total_late_minutes += $entry['late_minutes'];
                                }
                            }
                        }
                    ?>
                        <div class="late-employee-card" style="background: white; border: 1px solid #fee2e2; border-radius: 12px; padding: 20px; box-shadow: 0 4px 12px rgba(239,68,68,0.08); transition: all 0.3s ease; position: relative; overflow: hidden;">
                            <!-- Card header -->
                            <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 16px;">
                                <div style="display: flex; align-items: center; gap: 12px;">
                                    <div style="width: 40px; height: 40px; background: linear-gradient(135deg, #f87171 0%, #ef4444 100%); border-radius: 10px; display: flex; align-items: center; justify-content: center;">
                                        <i class="fa-solid fa-user" style="color: white; font-size: 16px;"></i>
                                    </div>
                                    <div>
                                        <h4 style="margin: 0 0 2px 0; color: #1f2937; font-size: 1.1em; font-weight: 600;"><?php echo htmlspecialchars($late['name']); ?></h4>
                                        <p style="margin: 0; color: #6b7280; font-size: 0.85em;"><?php echo htmlspecialchars($late['employee_id']); ?></p>
                                    </div>
                                </div>

                                <div style="display: flex; align-items: center; gap: 8px;">
                                    <?php if ((int)$late['late_count'] > 1): ?>
                                        <span class="late-count-badge" style="background: #fef3c7; color: #d97706; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600; border: 1px solid #fcd34d;">
                                            x<?php echo (int)$late['late_count']; ?>
                                        </span>
                                    <?php endif; ?>

                                    <button type="button" class="late-toggle-btn" data-target="#late-dd-<?php echo $emp_safe; ?>" style="width: 32px; height: 32px; border: 1px solid #e5e7eb; background: #f9fafb; border-radius: 8px; display: flex; align-items: center; justify-content: center; cursor: pointer; transition: all 0.2s ease; color: #6b7280;">
                                        <i class="fa-solid fa-chevron-down" style="font-size: 12px; transition: transform 0.2s ease;"></i>
                                    </button>
                                </div>
                            </div>

                            <!-- Late summary -->
                            <?php if ($total_late_minutes > 0): ?>
                                <div style="background: #fef2f2; border: 1px solid #fecaca; border-radius: 8px; padding: 12px; margin-bottom: 16px;">
                                    <div style="display: flex; align-items: center; gap: 8px; color: #dc2626; font-weight: 600; font-size: 0.9em;">
                                        <i class="fa-solid fa-clock"></i>
                                        <span>សរុបយឺត: <?php echo format_late_minutes($total_late_minutes); ?></span>
                                    </div>
                                </div>
                            <?php endif; ?>

                            <!-- Dropdown panel -->
                            <div id="late-dd-<?php echo $emp_safe; ?>" class="late-details-panel" style="display: none; border-top: 1px solid #f3f4f6; padding-top: 16px; margin-top: 16px;">
                                <?php if (empty($late['entries'])): ?>
                                    <div style="color: #6b7280; font-style: italic; text-align: center; padding: 20px;">
                                        <i class="fa-solid fa-info-circle" style="margin-bottom: 8px; display: block;"></i>
                                        មិនមានព័ត៌មានលម្អិត
                                    </div>
                                <?php else: ?>
                                    <div style="display: flex; flex-direction: column; gap: 8px;">
                                        <h5 style="margin: 0 0 12px 0; color: #374151; font-size: 0.95em; font-weight: 600; display: flex; align-items: center; gap: 8px;">
                                            <i class="fa-solid fa-location-dot"></i>
                                            ព័ត៌មានលម្អិត
                                        </h5>
                                        <div style="display: flex; flex-direction: column; gap: 8px;">
                                            <?php foreach ($late['entries'] as $entry):
                                                $location_name = $entry['location_name'] ?? 'Unknown';
                                                $time = date('h:i A', strtotime($entry['log_datetime']));
                                            ?>
                                                <div style="background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 8px; padding: 12px; display: flex; align-items: center; justify-content: space-between;">
                                                    <div style="display: flex; align-items: center; gap: 10px;">
                                                        <div style="width: 32px; height: 32px; background: #e5e7eb; border-radius: 6px; display: flex; align-items: center; justify-content: center;">
                                                            <i class="fa-solid fa-map-marker-alt" style="color: #6b7280; font-size: 12px;"></i>
                                                        </div>
                                                        <div>
                                                            <div style="font-weight: 500; color: #374151; font-size: 0.9em;"><?php echo htmlspecialchars($location_name); ?></div>
                                                            <div style="color: #6b7280; font-size: 0.8em;"><?php echo $time; ?></div>
                                                        </div>
                                                    </div>
                                                    <?php if(isset($entry['late_minutes']) && $entry['late_minutes'] !== null): ?>
                                                        <div style="background: #dc2626; color: white; padding: 4px 8px; border-radius: 12px; font-size: 0.75em; font-weight: 600;">
                                                            +<?php echo htmlspecialchars(format_late_minutes($entry['late_minutes'])); ?>
                                                        </div>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endforeach; ?>
                                        </div>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    <?php endforeach; ?>
                </div>
            <?php endif; ?>
        </div>
    </div>



    <div class="reports-heading" style="margin-top: 24px; display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:12px;">
        <div style="display:flex; align-items:center; gap:8px; flex-wrap:wrap;">
            <h3 style="margin: 0; display:flex; align-items:center; gap:8px;">
                <i class="fa-solid fa-list-ul"></i> បញ្ជីវត្តមានលម្អិត
            </h3>
            <span id="attendanceSelectionInfo" class="attendance-selection-info" style="display:none;">បានជ្រើស <strong>0</strong></span>
        </div>
        <div style="display:flex; gap:8px; align-items:center;">
            <button id="createReportBtn" type="button" class="btn btn-primary btn-sm"><i class="fa-solid fa-plus-circle"></i> បង្កើតរបាយការណ៍វត្តមាន</button>
            <button id="exportExcelBtn" type="button" class="btn btn-success btn-sm"><i class="fa-solid fa-file-excel"></i> នាំចេញជា Excel (xlsx)</button>
            <button id="deleteSelectedBtn" type="button" class="btn btn-danger btn-sm" disabled><i class="fa-solid fa-trash"></i> លុបជ្រើសរើស</button>
            <button id="clearAttendanceSelection" type="button" class="btn btn-sm btn-outline-secondary" style="display:none;">
                <i class="fa-solid fa-eraser"></i> សម្អាតជ្រើសរើស
            </button>
            <button id="toggleReportsFullscreen" type="button" class="icon-btn" title="បង្ហាញពេញអេក្រង់"><i class="fa-solid fa-expand"></i></button>
        </div>
    </div>

    <div class="department-navtabs">
        <?php
            // Build base query params to preserve current filters when switching tabs
            $base_tab_params = [
                'page' => 'reports',
                'filter_date' => $filter_date,
                'filter_status' => $filter_status,
            ];
        ?>
        <ul class="nav nav-tabs" id="departmentTabs" style="list-style:none;">
            <li class="nav-item">
                <?php $q = array_merge($base_tab_params, ['filter_department' => 'department']); ?>
                <a class="nav-link <?php echo ($filter_department === 'department') ? 'active' : ''; ?>" href="?<?php echo http_build_query($q); ?>" data-dept="department">
                    <i class="fa-solid fa-briefcase"></i> ជំនាញ
                </a>
            </li>
            <li class="nav-item">
                <?php $q = array_merge($base_tab_params, ['filter_department' => 'worker']); ?>
                <a class="nav-link <?php echo ($filter_department === 'worker') ? 'active' : ''; ?>" href="?<?php echo http_build_query($q); ?>" data-dept="worker">
                    <i class="fa-solid fa-users"></i> កម្មករ
                </a>
            </li>
        </ul>
    </div>

    <form method="GET" action="admin_attendance.php" style="margin:12px 0 20px 0; padding:12px; background: #ffffff; border-radius:8px;">
        <input type="hidden" name="page" value="reports">
        <input type="hidden" name="filter_department" value="<?php echo htmlspecialchars($filter_department); ?>">
        <div style="display:flex; gap:12px; align-items:flex-end; flex-wrap:wrap;">
            <div class="form-group" style="min-width:220px;">
                <label for="filter_date"><i class="fa-solid fa-calendar-days"></i> ជ្រើសរើសកាលបរិច្ឆេទ</label>
                <select id="filter_date" name="filter_date" class="form-control" onchange="this.form.submit()">
                    <?php if (empty($available_dates)): ?>
                        <option value="<?php echo date('Y-m-d'); ?>">មិនមានទិន្នន័យ</option>
                    <?php else: ?>
                        <?php foreach ($available_dates as $date_option): ?>
                            <option value="<?php echo $date_option; ?>" <?php echo ($filter_date == $date_option) ? 'selected' : ''; ?>>
                                <?php echo date('d/m/Y', strtotime($date_option)); ?>
                            </option>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </select>
            </div>
            <div class="form-group" style="min-width:180px;">
                <label for="filter_status"><i class="fa-solid fa-handshake"></i> ស្ថានភាព</label>
                <select id="filter_status" name="filter_status" class="form-control" onchange="this.form.submit()">
                    <option value="All" <?php echo ($filter_status == 'All') ? 'selected' : ''; ?>>ទាំងអស់</option>
                    <option value="Good" <?php echo ($filter_status == 'Good') ? 'selected' : ''; ?>>ទាន់ពេល (Good)</option>
                    <option value="Late" <?php echo ($filter_status == 'Late') ? 'selected' : ''; ?>>យឺត (Late)</option>
                </select>
            </div>
        </div>
    </form>

    <div class="reports-table-wrapper" id="reportsTableWrapper"  style="margin-top: 2rem;" data-dh-count="<?php echo count($dynamic_headers); ?>">
    <table class="table" id="reportsTable">
        <thead>
            <tr>
                <th data-col="select" style="width:48px; text-align:center;"><input type="checkbox" id="selectAllReports" title="ជ្រើសរើសទាំងអស់"></th>
                <th data-col="employee_id"><i class="fa-solid fa-hashtag"></i> អត្តលេខ</th>
                <th data-col="name"><i class="fa-solid fa-user"></i> ឈ្មោះ</th>
                <th data-col="location_name"><i class="fa-solid fa-map-location-dot"></i> ទីតាំង</th>
                <!-- Dynamic Headers -->
                <?php foreach ($dynamic_headers as $field_key => $label): ?>
                    <th data-col="<?php echo htmlspecialchars($field_key); ?>"><i class="fa-solid fa-info-circle"></i> <?php echo htmlspecialchars($label); ?></th>
                <?php endforeach; ?>
                <th data-col="action_type"><i class="fa-solid fa-person-walking"></i> សកម្មភាព</th>
                <th data-col="log_date"><i class="fa-solid fa-calendar-days"></i> ថ្ងៃខែឆ្នាំ</th>
                <th data-col="log_time"><i class="fa-solid fa-clock"></i> ពេលវេលា</th>
                <th data-col="status"><i class="fa-solid fa-circle-info"></i> ស្ថានភាព</th>
                <th data-col="late_reason"><i class="fa-solid fa-comment-dots"></i> មូលហេតុ</th>
                <th data-col="noted"><i class="fa-solid fa-sticky-note"></i> Noted</th>
                <th data-col="operations"><i class="fa-solid fa-sliders"></i> សកម្មភាព</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($report_data)): ?>
                <tr><td colspan="<?php echo 11 + count($dynamic_headers); ?>" style="text-align: center; font-style: italic;">មិនមានទិន្នន័យវត្តមានសម្រាប់ថ្ងៃដែលបានជ្រើសរើសទេ។</td></tr>
            <?php else: ?>
                <?php foreach ($report_data as $log):
                    // [កូដដែលបានកែសម្រួល] Decode ข้อมูล JSON ที่បានบันทึกไว้
                    $saved_custom_data = json_decode($log['custom_fields_data'] ?? '{}', true);
                    // NEW: per-row late minutes calculation (cached per employee)
                    static $expected_checkin_cache = [];
                    $late_status_minutes = null;
                    if (strcasecmp($log['status'] ?? '', 'Late') === 0) {
                        // Prefer stored late_minutes
                        if (isset($log['late_minutes']) && (int)$log['late_minutes'] > 0) {
                            $late_status_minutes = (int)$log['late_minutes'];
                        } else {
                            $empIdCalc = $log['employee_id'] ?? '';
                            $current_hms = date('H:i:s', strtotime($log['log_datetime']));
                            $pivot_time_row = '';
                            $type = 'checkin';
                            if ($stmt_pv_r = $mysqli->prepare("SELECT end_time FROM attendance_rules WHERE employee_id = ? AND type = ? AND status = 'Good' AND end_time <= ? ORDER BY end_time DESC LIMIT 1")) {
                                $stmt_pv_r->bind_param('sss', $empIdCalc, $type, $current_hms);
                                if ($stmt_pv_r->execute()) {
                                    $res_pv_r = $stmt_pv_r->get_result();
                                    if ($row_pv_r = $res_pv_r->fetch_assoc()) { $pivot_time_row = $row_pv_r['end_time']; }
                                }
                                $stmt_pv_r->close();
                            }
                            if ($pivot_time_row === '') {
                                if ($stmt_ec_r = $mysqli->prepare("SELECT start_time FROM attendance_rules WHERE employee_id = ? AND type='checkin' ORDER BY start_time ASC LIMIT 1")) {
                                    $stmt_ec_r->bind_param('s', $empIdCalc);
                                    if ($stmt_ec_r->execute()) {
                                        $res_ec_r = $stmt_ec_r->get_result();
                                        if ($row_ec_r = $res_ec_r->fetch_assoc()) { $pivot_time_row = trim($row_ec_r['start_time'] ?? ''); }
                                    }
                                    $stmt_ec_r->close();
                                }
                            }
                            if ($pivot_time_row !== '' && preg_match('/^\d{1,2}:\d{2}$/', $pivot_time_row)) { $pivot_time_row .= ':00'; }
                            $et_final = $pivot_time_row;
                            if ($et_final !== '') {
                                $base_dt_row = date('Y-m-d', strtotime($log['log_datetime'])) . ' ' . $et_final;
                                $late_secs_row = strtotime($log['log_datetime']) - strtotime($base_dt_row);
                                if ($late_secs_row > 0) {
                                    // FIX: Use ceil for accuracy
                                    $late_status_minutes = (int)ceil($late_secs_row / 60);
                                }
                            }
                        }
                    }
                ?>
                    <?php $log_pk_val = (int)($log['id'] ?? $log['log_id'] ?? $log['checkin_id'] ?? 0); ?>
                    <tr data-log-pk="<?php echo $log_pk_val; ?>" data-emp="<?php echo htmlspecialchars($log['employee_id']); ?>" data-dt="<?php echo htmlspecialchars($log['log_datetime']); ?>">
                        <td class="col-select" style="text-align:center;"><input type="checkbox" class="report-select" data-id="<?php echo $log_pk_val; ?>"></td>
                        <td class="col-employee_id"><?php echo htmlspecialchars($log['employee_id']); ?></td>
                        <td class="col-name" style="font-weight: bold; font-size:18px; color: #004085;"><?php echo htmlspecialchars($log['name']); ?></td>
                        <td class="col-location_name"><?php echo htmlspecialchars($log['location_name'] ?? ''); ?></td>

                        <!-- Dynamic Field cells -->
                        <?php foreach ($dynamic_headers as $key => $label): ?>
                            <td class="col-<?php echo htmlspecialchars($key); ?>"><?php echo htmlspecialchars($saved_custom_data[$key] ?? $saved_custom_data[$label] ?? 'N/A'); ?></td>
                        <?php endforeach; ?>

                        <td class="col-action_type"><?php echo htmlspecialchars($log['action_type']); ?></td>
                        <td class="col-log_date"><?php echo date('d/m/Y', strtotime($log['log_datetime'])); ?></td>
                        <td class="col-log_time"><?php echo date('h:i:s A', strtotime($log['log_datetime'])); ?></td>
                        <td class="col-status">
                            <?php
                            $status_class = (strtolower($log['status'] ?? '') == 'late') ? 'status-late' : 'status-good';
                            $status_icon = (strtolower($log['status'] ?? '') == 'late') ? '<i class="fa-solid fa-hourglass-end"></i> ' : '<i class="fa-solid fa-circle-check"></i> ';
                            $status_text_render = htmlspecialchars($log['status'] ?? 'Good');
                            if ($late_status_minutes !== null) { $status_text_render .= ' (' . format_late_minutes($late_status_minutes) . ')'; }
                            echo "<span class='{$status_class}'>" . $status_icon . $status_text_render . "</span>";
                            ?>
                        </td>
                        <td class="col-late_reason late-reason-cell"><?php echo htmlspecialchars($log['late_reason'] ?? 'N/A'); ?></td>
                        <td class="col-noted noted-cell" contenteditable="true" data-log-id="<?php echo $log_pk_val; ?>">
                            <?php
                            $noted = $log['noted'] ?? '';
                            if (filter_var($noted, FILTER_VALIDATE_URL)) {
                                echo '<a href="' . htmlspecialchars($noted) . '" target="_blank" rel="noopener noreferrer">' . htmlspecialchars($noted) . '</a>';
                            } else {
                                echo htmlspecialchars($noted);
                            }
                            ?>
                        </td>
                        <td>
                            <div class="action-dropdown-container">
                                <button type="button" class="action-toggle-btn" title="សកម្មភាព">
                                    <i class="fa-solid fa-circle-chevron-down"></i>
                                </button>
                                <div class="action-dropdown-menu" style="display: none;">
                                    <button type="button"
                                        class="btn btn-primary btn-sm edit-late-reason"
                                        data-log-id="<?php echo $log_pk_val; ?>"
                                        data-emp-id="<?php echo htmlspecialchars($log['employee_id']); ?>"
                                        data-log-dt="<?php echo htmlspecialchars($log['log_datetime']); ?>"
                                        data-current-reason="<?php echo htmlspecialchars($log['late_reason'] ?? '', ENT_QUOTES, 'UTF-8'); ?>">
                                        <i class="fa-solid fa-pen-to-square"></i> View/Edit
                                    </button>
                                </div>
                            </div>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>
    </div>

    <?php
    if ($total_pages > 1):
        $query_params = [
            'page' => 'reports',
            'filter_date' => $filter_date,
            'filter_status' => $filter_status,
            'filter_department' => $filter_department
        ];
    ?>
    <nav>
        <ul class="pagination">
            <li class="<?php if($current_p_page <= 1){ echo 'disabled'; } ?>">
                <a href="<?php if($current_p_page > 1){ echo '?' . http_build_query(array_merge($query_params, ['p' => $current_p_page - 1])); } else { echo '#'; } ?>">Previous</a>
            </li>

            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
            <li class="<?php if($current_p_page == $i) {echo 'active'; } ?>">
                <a href="?<?php echo http_build_query(array_merge($query_params, ['p' => $i])); ?>"><?php echo $i; ?></a>
            </li>
            <?php endfor; ?>

            <li class="<?php if($current_p_page >= $total_pages) { echo 'disabled'; } ?>">
                <a href="<?php if($current_p_page < $total_pages) { echo '?' . http_build_query(array_merge($query_params, ['p' => $current_p_page + 1])); } else { echo '#'; } ?>">Next</a>
            </li>
        </ul>
    </nav>
    <?php endif; ?>

    <!-- Hidden export-only full table (no pagination, no action column) -->
     <table class="table" id="reportsTableExport" style="display:none;">
        <thead>
            <tr>
                <th data-col="employee_id">អត្តលេខ</th>
                <th data-col="name">ឈ្មោះ</th>
                <th data-col="location_name">ទីតាំង</th>
                <!-- Dynamic Headers for export -->
                <?php foreach ($dynamic_headers as $key => $label): ?>
                    <th data-col="<?php echo htmlspecialchars($key); ?>"><?php echo htmlspecialchars($label); ?></th>
                <?php endforeach; ?>
                <th data-col="action_type">ប្រភេទវត្តមាន</th>
                <th data-col="log_date">ថ្ងៃខែឆ្នាំ</th>
                <th data-col="log_time">ពេលវេលា</th>
                <th data-col="status">ស្ថានភាព</th>
                <th data-col="late_reason">មូលហេតុ</th>
                <th data-col="noted">Noted</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($export_data)): ?>
                <tr><td colspan="<?php echo 9 + count($dynamic_headers); ?>">មិនមានទិន្នន័យ</td></tr>
            <?php else: ?>
                <?php foreach ($export_data as $log):
                    // [UPDATED] Include late minutes calc + row data attributes for fullscreen cloning
                    $saved_custom_data = json_decode($log['custom_fields_data'] ?? '{}', true);
                    $status_raw = trim($log['status'] ?? 'Good');
                    $late_reason = htmlspecialchars($log['late_reason'] ?? 'N/A');
                    // Reuse expected checkin pivot logic (prefer latest Good end_time <= log time, fallback to earliest start_time)
                    static $expected_checkin_cache_export = [];
                    $late_status_minutes = null;
                    $empIdCalc = $log['employee_id'] ?? '';
                    if (strcasecmp($status_raw, 'Late') === 0 && $empIdCalc !== '') {
                        // Prefer stored late_minutes
                        if (isset($log['late_minutes']) && (int)$log['late_minutes'] > 0) {
                            $late_status_minutes = (int)$log['late_minutes'];
                        } else {
                            if (!isset($expected_checkin_cache_export[$empIdCalc])) {
                                $et = '';
                                // Use pivot logic: latest end_time with status='Good' that is <= current log time (H:i:s)
                                $current_hms_row = date('H:i:s', strtotime($log['log_datetime']));
                                if ($stmt_pivot = $mysqli->prepare("SELECT end_time FROM attendance_rules WHERE employee_id = ? AND type='checkin' AND status = 'Good' AND end_time <= ? ORDER BY end_time DESC LIMIT 1")) {
                                    $stmt_pivot->bind_param('ss', $empIdCalc, $current_hms_row);
                                    if ($stmt_pivot->execute()) {
                                        $res_pivot = $stmt_pivot->get_result();
                                        if ($row_pivot = $res_pivot->fetch_assoc()) { $et = trim($row_pivot['end_time'] ?? ''); }
                                    }
                                    $stmt_pivot->close();
                                }
                                // Fallback to earliest start_time if pivot not found
                                if ($et === '') {
                                    if ($stmt_f = $mysqli->prepare("SELECT start_time FROM attendance_rules WHERE employee_id = ? AND type='checkin' ORDER BY start_time ASC LIMIT 1")) {
                                        $stmt_f->bind_param('s', $empIdCalc);
                                        if ($stmt_f->execute()) {
                                            $res_f = $stmt_f->get_result();
                                            if ($row_f = $res_f->fetch_assoc()) { $et = trim($row_f['start_time'] ?? ''); }
                                        }
                                        $stmt_f->close();
                                    }
                                }
                                if ($et !== '' && preg_match('/^\d{1,2}:\d{2}$/', $et)) { $et .= ':00'; }
                                $expected_checkin_cache_export[$empIdCalc] = $et; // may be ''
                            }
                            $et_final = $expected_checkin_cache_export[$empIdCalc];
                            if ($et_final !== '') {
                                $base_dt_row = date('Y-m-d', strtotime($log['log_datetime'])) . ' ' . $et_final;
                                $late_secs_row = strtotime($log['log_datetime']) - strtotime($base_dt_row);
                                if ($late_secs_row > 0) {
                                    // FIX: Use ceil for accuracy
                                    $late_status_minutes = (int)ceil($late_secs_row / 60);
                                }
                            }
                        }
                    }
                    $status_text_raw = $status_raw . ($late_status_minutes !== null ? ' (' . format_late_minutes($late_status_minutes) . ')' : '');
                    $status_text = htmlspecialchars($status_text_raw);
                    $log_pk_val = (int)($log['id'] ?? $log['log_id'] ?? $log['checkin_id'] ?? 0);
                ?>
                    <tr data-log-pk="<?php echo $log_pk_val; ?>" data-emp="<?php echo htmlspecialchars($log['employee_id']); ?>" data-dt="<?php echo htmlspecialchars($log['log_datetime']); ?>">
                        <td class="col-employee_id"><?php echo htmlspecialchars($log['employee_id']); ?></td>
                        <td class="col-name"><?php echo htmlspecialchars($log['name']); ?></td>
                        <td class="col-location_name"><?php echo htmlspecialchars($log['location_name'] ?? ''); ?></td>

                        <!-- Dynamic custom field columns -->
                        <?php foreach ($dynamic_headers as $key => $label): ?>
                            <td class="col-<?php echo htmlspecialchars($key); ?>"><?php echo htmlspecialchars($saved_custom_data[$key] ?? $saved_custom_data[$label] ?? ''); ?></td>
                        <?php endforeach; ?>

                        <td class="col-action_type"><?php echo htmlspecialchars($log['action_type']); ?></td>
                        <td class="col-log_date"><?php echo date('d/m/Y', strtotime($log['log_datetime'])); ?></td>
                        <td class="col-log_time"><?php echo date('h:i:s A', strtotime($log['log_datetime'])); ?></td>
                        <td class="col-status"><?php echo $status_text; ?></td>
                        <td class="col-late_reason"><?php echo $late_reason; ?></td>
                        <td class="col-noted">
                            <?php
                            $noted = $log['noted'] ?? '';
                            if (filter_var($noted, FILTER_VALIDATE_URL)) {
                                echo '<a href="' . htmlspecialchars($noted) . '" target="_blank" rel="noopener noreferrer">' . htmlspecialchars($noted) . '</a>';
                            } else {
                                echo htmlspecialchars($noted);
                            }
                            ?>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>

    <!-- Create Report Modal -->
    <div id="createReportModal" class="colvis-modal" style="display:none;">
        <div class="colvis-panel">
            <h4 style="border-bottom: 1px solid #eee; padding-bottom: 10px; margin-bottom: 15px;">
                <i class="fa-solid fa-square-poll-vertical"></i> បង្កើតរបាយការណ៍វត្តមាន
            </h4>
            <form id="createReportForm">
                <div class="form-group" style="margin-bottom: 15px;">
                    <label style="font-weight: 600; font-size: 0.9em; color: #555; margin-bottom: 5px; display: block;">ប្រភេទរបាយការណ៍:</label>
                    <select id="report_type_select" class="form-control" name="report_type" style="width: 100%;">
                        <option value="daily">របាយការណ៍ប្រចាំថ្ងៃ (Daily Details)</option>
                        <option value="late_summary">របាយការណ៍យឺតសរុប (Late Summary)</option>
                        <option value="forgotten">របាយការណ៍ភ្លេចស្កេន (Forgotten Scan)</option>
                    </select>
                </div>
                <div class="form-group" style="margin-bottom: 15px;">
                    <label id="start_date_label" style="font-weight: 600; font-size: 0.9em; color: #555; margin-bottom: 5px; display: block;">កាលបរិច្ឆេទ:</label>
                    <input type="date" class="form-control" name="start_date" value="<?php echo $filter_date; ?>" style="width: 100%;">
                </div>
                <div id="end_date_group" class="form-group" style="margin-bottom: 15px; display:none;">
                    <label style="font-weight: 600; font-size: 0.9em; color: #555; margin-bottom: 5px; display: block;">ដល់ថ្ងៃ:</label>
                    <input type="date" class="form-control" name="end_date" value="<?php echo $filter_date; ?>" style="width: 100%;">
                </div>
                <div class="form-group" style="margin-bottom: 15px;">
                    <label style="font-weight: 600; font-size: 0.9em; color: #555; margin-bottom: 5px; display: block;">ជំនាញ/កម្មករ:</label>
                    <select class="form-control" name="filter_department_select" style="width: 100%;">
                        <option value="department" <?php echo ($filter_department == 'department') ? 'selected' : ''; ?>>ជំនាញ (Department)</option>
                        <option value="worker" <?php echo ($filter_department == 'worker') ? 'selected' : ''; ?>>កម្មករ (Worker)</option>
                    </select>
                </div>
                <div class="colvis-actions" style="border-top: 1px solid #eee; padding-top: 15px; margin-top: 15px;">
                    <button type="button" id="closeCreateReportModal" class="btn btn-sm btn-outline-secondary">បោះបង់ (Cancel)</button>
                    <button type="submit" class="btn btn-primary btn-sm"><i class="fa-solid fa-eye"></i> បង្ហាញរបាយការណ៍</button>
                </div>
            </form>
        </div>
    </div>

<?php endif; ?>

<!-- Column visibility controls + JS -->
<style>
    .colvis-modal { position: fixed; left: 0; top: 0; right:0; bottom:0; background: rgba(0,0,0,0.45); display:flex; align-items:center; justify-content:center; z-index:9999; }
    .colvis-panel { background: #fff; padding: 18px; border-radius: 8px; width: 480px; max-width: 95%; box-shadow: 0 8px 30px rgba(0,0,0,0.2); }
    .colvis-panel h4 { margin: 0 0 12px 0; }
    .colvis-list { max-height: 320px; overflow:auto; display:flex; flex-wrap:wrap; gap:8px; }
    .colvis-item { width: 48%; display:flex; align-items:center; gap:8px; }
    .colvis-actions { margin-top: 12px; display:flex; justify-content:flex-end; gap:8px; }
</style>

<script>
(function(){
    const wrapper = document.getElementById('reportsTableWrapper');
    if (!wrapper) return;

    // Insert button into the controls area if present
    const controlsParent = document.querySelector('.header .right-actions') || document.body;
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.id = 'columnToggleBtn';
    btn.className = 'btn btn-sm';
    btn.style.marginLeft = '8px';
    btn.innerHTML = '<i class="fa-solid fa-table-columns"></i> កំណត់តារាងជួរឈរ';
    // append near top controls
    if (controlsParent) controlsParent.appendChild(btn);

    function getHeaders() {
        const ths = Array.from(document.querySelectorAll('#reportsTable thead th[data-col]'));
        return ths.map(t=>({key: t.getAttribute('data-col'), label: (t.textContent||t.innerText).trim()}));
    }

    function applyVisibility(map) {
        const headers = getHeaders();
        headers.forEach(h=>{
            const show = (map[h.key] === undefined) ? 1 : (parseInt(map[h.key]) === 1);
            const th = document.querySelector('#reportsTable thead th[data-col="'+h.key+'"]');
            if (th) th.style.display = show ? '' : 'none';
            const tds = document.querySelectorAll('.col-'+h.key);
            tds.forEach(td=> td.style.display = show ? '' : 'none');
            // also hide export table header/cols
            const thExp = document.querySelector('#reportsTableExport thead th[data-col="'+h.key+'"]'); if (thExp) thExp.style.display = show ? '' : 'none';
            const tdsExp = document.querySelectorAll('#reportsTableExport .col-'+h.key); tdsExp.forEach(td=> td.style.display = show ? '' : 'none');
        });
    }

    async function loadVisibility() {
        try {
            const fd = new FormData(); fd.append('ajax_action','get_column_visibility');
            const res = await fetch('admin_attendance.php', {method:'POST', body: fd});
            const j = await res.json();
            if (j && j.status === 'success') { applyVisibility(j.data || {}); }
        } catch(e) { console.error('colvis load error', e); }
    }

    function openPanel(currentMap) {
        const headers = getHeaders();
        const modal = document.createElement('div'); modal.className = 'colvis-modal';
        const panel = document.createElement('div'); panel.className = 'colvis-panel';
        panel.innerHTML = '<h4>បង្ហាញ/លាក់ ជួរឈរ</h4>';
        const list = document.createElement('div'); list.className = 'colvis-list';
        headers.forEach(h=>{
            const item = document.createElement('label'); item.className='colvis-item';
            const chk = document.createElement('input'); chk.type='checkbox'; chk.value=h.key; chk.checked = (currentMap[h.key]===undefined) ? true : (parseInt(currentMap[h.key])===1);
            const span = document.createElement('span'); span.textContent = h.label;
            item.appendChild(chk); item.appendChild(span); list.appendChild(item);
        });
        panel.appendChild(list);
        const actions = document.createElement('div'); actions.className='colvis-actions';
        const btnCancel = document.createElement('button'); btnCancel.type='button'; btnCancel.className='btn btn-sm'; btnCancel.textContent='Cancel';
        const btnSave = document.createElement('button'); btnSave.type='button'; btnSave.className='btn btn-primary btn-sm'; btnSave.textContent='Save';
        actions.appendChild(btnCancel); actions.appendChild(btnSave); panel.appendChild(actions);
        modal.appendChild(panel); document.body.appendChild(modal);

        btnCancel.addEventListener('click', ()=> modal.remove());
        btnSave.addEventListener('click', async ()=>{
            const boxes = list.querySelectorAll('input[type="checkbox"]');
            const map = {};
            boxes.forEach(b=> map[b.value] = b.checked ? 1 : 0);
            // send to server
            try {
                const fd = new FormData(); fd.append('ajax_action','save_column_visibility'); fd.append('visibility', JSON.stringify(map));
                const res = await fetch('admin_attendance.php', {method:'POST', body: fd});
                const j = await res.json();
                if (j && j.status === 'success') {
                    applyVisibility(map);
                } else {
                    alert('Save failed: ' + (j.message||'unknown'));
                }
            } catch(e) { alert('Save error'); console.error(e); }
            modal.remove();
        });
    }

    btn.addEventListener('click', async function(){
        // fetch current visibility then open panel
        try {
            const fd = new FormData(); fd.append('ajax_action','get_column_visibility');
            const res = await fetch('admin_attendance.php', {method:'POST', body: fd});
            const j = await res.json();
            const map = (j && j.status==='success')? (j.data||{}) : {};
            openPanel(map);
        } catch(e) { console.error(e); openPanel({}); }
    });

    // Create Report Modal Handlers
    const createReportBtn = document.getElementById('createReportBtn');
    const createReportModal = document.getElementById('createReportModal');
    const closeCreateReportModal = document.getElementById('closeCreateReportModal');
    const reportTypeSelect = document.getElementById('report_type_select');
    const endDateGroup = document.getElementById('end_date_group');
    const createReportForm = document.getElementById('createReportForm');

    if (createReportBtn && createReportModal) {
        createReportBtn.addEventListener('click', () => {
            createReportModal.style.display = 'flex';
        });

        if (closeCreateReportModal) {
            closeCreateReportModal.addEventListener('click', () => {
                createReportModal.style.display = 'none';
            });
        }

        createReportModal.addEventListener('click', (e) => {
            if (e.target === createReportModal) createReportModal.style.display = 'none';
        });

        if (reportTypeSelect) {
            reportTypeSelect.addEventListener('change', function() {
                const startDateLabel = document.getElementById('start_date_label');
                if (this.value === 'daily') {
                    if (endDateGroup) endDateGroup.style.display = 'none';
                    if (startDateLabel) startDateLabel.textContent = 'កាលបរិច្ឆេទ:';
                } else {
                    if (endDateGroup) endDateGroup.style.display = 'block';
                    if (startDateLabel) startDateLabel.textContent = 'ចាប់ពីថ្ងៃ:';
                }
            });
        }

        if (createReportForm) {
            createReportForm.addEventListener('submit', function(e) {
                e.preventDefault();
                const type = reportTypeSelect.value;
                const start = this.start_date.value;
                const end = this.end_date.value;
                const dept = this.filter_department_select.value;

                let params = new URLSearchParams();
                if (type === 'daily') {
                    params.append('page', 'reports');
                    params.append('filter_date', start);
                    params.append('filter_status', 'All');
                    params.append('filter_department', dept);
                } else if (type === 'late_summary') {
                    params.append('page', 'reports');
                    params.append('action', 'late_report_summary');
                    params.append('start_date', start);
                    params.append('end_date', end);
                    params.append('filter_department', dept);
                } else if (type === 'forgotten') {
                    params.append('page', 'reports');
                    params.append('action', 'forgotten_scan_report');
                    params.append('start_date', start);
                    params.append('end_date', end);
                    params.append('filter_department', dept);
                }
                window.location.href = 'admin_attendance.php?' + params.toString();
            });
        }
    }

    // initial load
    loadVisibility();
})();
</script>

<script>
// Expose a global helper so sidebar link can open the Column Visibility panel
function openColumnVisibility() {
    try {
        var btn = document.getElementById('columnToggleBtn');
        if (btn) { btn.click(); return; }
    } catch (e) {
        // ignore
    }
    alert('Column Visibility panel is not ready yet. Please try reloading the page.');
}
</script>

<?php if ($current_action == 'late_report_summary' && hasPageAccess($mysqli, 'reports', 'late_report_summary', $admin_id_check)): ?>
    <?php
    $start_date = $_GET['start_date'] ?? date('Y-m-01');
    $end_date = $_GET['end_date'] ?? date('Y-m-t');
    $filter_department = $_GET['filter_department'] ?? 'department';

    // Fetch all users for this admin
    $users_sql = "SELECT employee_id, name, custom_data FROM users " . ($is_super_admin ? "" : "WHERE created_by_admin_id = ?");
    $stmt_u = $mysqli->prepare($users_sql);
    if (!$is_super_admin) { $stmt_u->bind_param("s", $current_admin_id); }
    $stmt_u->execute();
    $users_res = $stmt_u->get_result();
    $all_users = $users_res->fetch_all(MYSQLI_ASSOC);
    $stmt_u->close();

    $report_rows = [];
    foreach ($all_users as $user) {
        $cdata = json_decode($user['custom_data'] ?? '{}', true);
        $dept = $cdata['department'] ?? 'Other';

        // Filter by department
        if ($filter_department === 'worker' && $dept !== 'Worker') continue;
        if ($filter_department === 'department' && $dept === 'Worker') continue;

        $emp_id = $user['employee_id'];
        $stats = ['under15' => 0, 'under1h' => 0, 'over1h' => 0, 'total' => 0];

        // Fetch all late logs for this user in range
        $logs_sql = "SELECT log_datetime FROM checkin_logs WHERE employee_id = ? AND DATE(log_datetime) BETWEEN ? AND ? AND status = 'Late'";
        if ($stmt_l = $mysqli->prepare($logs_sql)) {
            $stmt_l->bind_param("sss", $emp_id, $start_date, $end_date);
            $stmt_l->execute();
            $logs_res = $stmt_l->get_result();
            while ($log = $logs_res->fetch_assoc()) {
                // Calculate late minutes
                $pivot_time = '';
                $log_hms = date('H:i:s', strtotime($log['log_datetime']));
                if ($stmt_pv = $mysqli->prepare("SELECT end_time FROM attendance_rules WHERE employee_id = ? AND type = 'checkin' AND status = 'Good' AND end_time <= ? ORDER BY end_time DESC LIMIT 1")) {
                    $stmt_pv->bind_param('ss', $emp_id, $log_hms);
                    $stmt_pv->execute();
                    $res_pv = $stmt_pv->get_result();
                    if ($row_pv = $res_pv->fetch_assoc()) { $pivot_time = $row_pv['end_time']; }
                    $stmt_pv->close();
                }
                if ($pivot_time === '') {
                    if ($stmt_ec = $mysqli->prepare("SELECT start_time FROM attendance_rules WHERE employee_id = ? AND type='checkin' ORDER BY start_time ASC LIMIT 1")) {
                        $stmt_ec->bind_param('s', $emp_id);
                        $stmt_ec->execute();
                        $res_ec = $stmt_ec->get_result();
                        if ($row_ec = $res_ec->fetch_assoc()) { $pivot_time = trim($row_ec['start_time'] ?? ''); }
                        $stmt_ec->close();
                    }
                }
                if ($pivot_time !== '') {
                    if (preg_match('/^\d{1,2}:\d{2}$/', $pivot_time)) { $pivot_time .= ':00'; }
                    $base_dt = date('Y-m-d', strtotime($log['log_datetime'])) . ' ' . $pivot_time;
                    $late_secs = strtotime($log['log_datetime']) - strtotime($base_dt);
                    if ($late_secs > 0) {
                        $mins = (int)floor($late_secs / 60);
                        if ($mins === 0) $mins = 1;

                        if ($mins < 15) $stats['under15']++;
                        elseif ($mins < 60) $stats['under1h']++;
                        else $stats['over1h']++;
                        $stats['total']++;
                    }
                }
            }
            $stmt_l->close();
        }

        $report_rows[] = [
            'id' => $user['employee_id'],
            'name' => $user['name'],
            'gender' => $cdata['gender'] ?? 'N/A',
            'position' => $cdata['position'] ?? 'N/A',
            'stats' => $stats
        ];
    }
    ?>
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
        <h2><i class="fa-solid fa-clock-rotate-left"></i> របាយការណ៍បុគ្គលិកមកយឺតសរុប</h2>
        <div style="display:flex; gap:8px;">
            <button onclick="printReport('late')" class="btn btn-info btn-sm"><i class="fa-solid fa-print"></i> បោះពុម្ព (Print)</button>
            <button onclick="exportTableToExcel('lateReportSummaryTable', 'Late_Report_Summary')" class="btn btn-success btn-sm"><i class="fa-solid fa-file-excel"></i> នាំចេញ Excel</button>
        </div>
    </div>

    <div class="department-navtabs">
        <ul class="nav nav-tabs">
            <li class="nav-item">
                <a class="nav-link <?php echo ($filter_department === 'department') ? 'active' : ''; ?>" href="?page=reports&action=late_report_summary&start_date=<?php echo $start_date; ?>&end_date=<?php echo $end_date; ?>&filter_department=department">
                    <i class="fa-solid fa-briefcase"></i> ជំនាញ
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo ($filter_department === 'worker') ? 'active' : ''; ?>" href="?page=reports&action=late_report_summary&start_date=<?php echo $start_date; ?>&end_date=<?php echo $end_date; ?>&filter_department=worker">
                    <i class="fa-solid fa-users"></i> កម្មករ
                </a>
            </li>
        </ul>
    </div>

    <form method="GET" style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; gap: 15px; align-items: flex-end;">
        <input type="hidden" name="page" value="reports">
        <input type="hidden" name="action" value="late_report_summary">
        <input type="hidden" name="filter_department" value="<?php echo htmlspecialchars($filter_department); ?>">
        <div class="form-group">
            <label>ចាប់ពីថ្ងៃ:</label>
            <input type="date" name="start_date" class="form-control" value="<?php echo $start_date; ?>">
        </div>
        <div class="form-group">
            <label>ដល់ថ្ងៃ:</label>
            <input type="date" name="end_date" class="form-control" value="<?php echo $end_date; ?>">
        </div>
        <button type="submit" class="btn btn-primary">បង្ហាញរបាយការណ៍</button>
    </form>

    <div class="table-container" style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        <table class="table" id="lateReportSummaryTable">
            <thead style="background: #2c3e50; color: white;">
                <tr>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">ល.រ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">អត្តលេខ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">ឈ្មោះ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">ភេទ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">តួនាទី</th>
                    <th colspan="3" style="text-align: center; background: #e67e22;">មកយឺត</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center; background: #c0392b;">សរុប</th>
                </tr>
                <tr>
                    <th style="text-align: center; background: #f39c12; font-size: 11px;">ក្រោម ១៥ នាទី</th>
                    <th style="text-align: center; background: #f39c12; font-size: 11px;">ចាប់ពី ១៥ នាទី</th>
                    <th style="text-align: center; background: #f39c12; font-size: 11px;">ចាប់ពី ១ ម៉ោង</th>
                </tr>
            </thead>
            <tbody>
                <?php
                    $total15=0; $totalH=0; $totalH1=0; $totalAll=0;
                    if (empty($report_rows)):
                ?>
                    <tr><td colspan="9" style="text-align:center;">មិនមានទិន្នន័យ</td></tr>
                <?php else: ?>
                    <?php $i=1; ?>
                    <?php foreach ($report_rows as $row): ?>
                        <tr>
                            <td style="text-align:center;"><?php echo $i++; ?></td>
                            <td style="text-align:center;"><?php echo htmlspecialchars($row['id']); ?></td>
                            <td style="font-weight:bold;"><?php echo htmlspecialchars($row['name']); ?></td>
                            <td style="text-align:center;"><?php echo htmlspecialchars($row['gender']); ?></td>
                            <td><?php echo htmlspecialchars($row['position']); ?></td>
                            <td style="text-align:center; font-weight:bold; color:<?php echo $row['stats']['under15']>0?'#d35400':'#7f8c8d'; ?>"><?php echo $row['stats']['under15']; ?></td>
                            <td style="text-align:center; font-weight:bold; color:<?php echo $row['stats']['under1h']>0?'#d35400':'#7f8c8d'; ?>"><?php echo $row['stats']['under1h']; ?></td>
                            <td style="text-align:center; font-weight:bold; color:<?php echo $row['stats']['over1h']>0?'#d35400':'#7f8c8d'; ?>"><?php echo $row['stats']['over1h']; ?></td>
                            <td style="text-align:center; font-weight:bold; background:#fdf2f2; color:#c0392b;"><?php echo $row['stats']['total']; ?></td>
                        </tr>
                        <?php
                            $total15 += $row['stats']['under15'];
                            $totalH += $row['stats']['under1h'];
                            $totalH1 += $row['stats']['over1h'];
                            $totalAll += $row['stats']['total'];
                        ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
            <tfoot style="background: #f1c40f; font-weight: bold;">
                <tr>
                    <td colspan="5" style="text-align: center;">សរុប</td>
                    <td style="text-align: center;"><?php echo $total15; ?></td>
                    <td style="text-align: center;"><?php echo $totalH; ?></td>
                    <td style="text-align: center;"><?php echo $totalH1; ?></td>
                    <td style="text-align: center;"><?php echo $totalAll; ?></td>
                </tr>
            </tfoot>
        </table>
    </div>

<?php elseif ($current_action == 'forgotten_scan_report' && hasPageAccess($mysqli, 'reports', 'forgotten_scan_report', $admin_id_check)): ?>
    <?php
    $start_date = $_GET['start_date'] ?? date('Y-m-01');
    $end_date = $_GET['end_date'] ?? date('Y-m-t');
    $filter_department = $_GET['filter_department'] ?? 'department';

    // Fetch all users for this admin
    $users_sql = "SELECT employee_id, name, custom_data FROM users " . ($is_super_admin ? "" : "WHERE created_by_admin_id = ?");
    $stmt_u = $mysqli->prepare($users_sql);
    if (!$is_super_admin) { $stmt_u->bind_param("s", $current_admin_id); }
    $stmt_u->execute();
    $users_res = $stmt_u->get_result();
    $all_users = $users_res->fetch_all(MYSQLI_ASSOC);
    $stmt_u->close();

    $report_rows = [];
    foreach ($all_users as $user) {
        $cdata = json_decode($user['custom_data'] ?? '{}', true);
        $dept = $cdata['department'] ?? 'Other';
        if ($filter_department === 'worker' && $dept !== 'Worker') continue;
        if ($filter_department === 'department' && $dept === 'Worker') continue;

        $emp_id = $user['employee_id'];
        $forgot_in = 0;
        $forgot_out = 0;

        // Fetch logs group by day
        $logs_sql = "SELECT DATE(log_datetime) as ldate, action_type FROM checkin_logs WHERE employee_id = ? AND DATE(log_datetime) BETWEEN ? AND ? ORDER BY log_datetime ASC";
        if ($stmt_l = $mysqli->prepare($logs_sql)) {
            $stmt_l->bind_param("sss", $emp_id, $start_date, $end_date);
            $stmt_l->execute();
            $logs_res = $stmt_l->get_result();
            $day_logs = [];
            while ($log = $logs_res->fetch_assoc()) {
                $day_logs[$log['ldate']][] = $log['action_type'];
            }
            $stmt_l->close();

            foreach ($day_logs as $date => $actions) {
                // Analysis logic for forgotten scans
                // (Check-In, Check-Out) is OK
                // (Check-In, Check-In) -> Forgot Out
                // (Check-Out, Check-Out) -> Forgot In
                // (Check-In, Check-In, Check-Out) -> Forgot Out

                $prev = null;
                foreach ($actions as $action) {
                    $action_norm = (stripos($action, 'In') !== false) ? 'IN' : 'OUT';
                    if ($prev === null) {
                        if ($action_norm === 'OUT') $forgot_in++;
                    } else {
                        if ($prev === $action_norm) {
                            if ($action_norm === 'IN') $forgot_out++;
                            else $forgot_in++;
                        }
                    }
                    $prev = $action_norm;
                }
                // If last action is IN, we assume they forgot to OUT (if it's not currently happening)
                // But only if today is not that day OR it's already late
                if ($prev === 'IN' && $date < date('Y-m-d')) {
                    $forgot_out++;
                }
            }
        }

        if ($forgot_in > 0 || $forgot_out > 0) {
            $report_rows[] = [
                'id' => $user['employee_id'],
                'name' => $user['name'],
                'gender' => $cdata['gender'] ?? 'N/A',
                'position' => $cdata['position'] ?? 'N/A',
                'forgot_in' => $forgot_in,
                'forgot_out' => $forgot_out,
                'total' => $forgot_in + $forgot_out
            ];
        }
    }
    ?>
    <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 20px;">
        <h2><i class="fa-solid fa-user-slash"></i> របាយការណ៍បុគ្គលិកភ្លេចស្កេន</h2>
        <div style="display:flex; gap:8px;">
            <button onclick="printReport('forgotten')" class="btn btn-info btn-sm"><i class="fa-solid fa-print"></i> បោះពុម្ព (Print)</button>
            <button onclick="exportTableToExcel('forgottenScanReportTable', 'Forgotten_Scan_Report')" class="btn btn-success btn-sm"><i class="fa-solid fa-file-excel"></i> នាំចេញ Excel</button>
        </div>
    </div>

    <div class="department-navtabs">
        <ul class="nav nav-tabs">
            <li class="nav-item">
                <a class="nav-link <?php echo ($filter_department === 'department') ? 'active' : ''; ?>" href="?page=reports&action=forgotten_scan_report&start_date=<?php echo $start_date; ?>&end_date=<?php echo $end_date; ?>&filter_department=department">
                    <i class="fa-solid fa-briefcase"></i> ជំនាញ
                </a>
            </li>
            <li class="nav-item">
                <a class="nav-link <?php echo ($filter_department === 'worker') ? 'active' : ''; ?>" href="?page=reports&action=forgotten_scan_report&start_date=<?php echo $start_date; ?>&end_date=<?php echo $end_date; ?>&filter_department=worker">
                    <i class="fa-solid fa-users"></i> កម្មករ
                </a>
            </li>
        </ul>
    </div>

    <form method="GET" style="background: white; padding: 15px; border-radius: 8px; margin-bottom: 20px; display: flex; gap: 15px; align-items: flex-end;">
        <input type="hidden" name="page" value="reports">
        <input type="hidden" name="action" value="forgotten_scan_report">
        <input type="hidden" name="filter_department" value="<?php echo htmlspecialchars($filter_department); ?>">
        <div class="form-group">
            <label>ចាប់ពីថ្ងៃ:</label>
            <input type="date" name="start_date" class="form-control" value="<?php echo $start_date; ?>">
        </div>
        <div class="form-group">
            <label>ដល់ថ្ងៃ:</label>
            <input type="date" name="end_date" class="form-control" value="<?php echo $end_date; ?>">
        </div>
        <button type="submit" class="btn btn-primary">បង្ហាញរបាយការណ៍</button>
    </form>

    <div class="table-container" style="background: white; padding: 20px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.05);">
        <table class="table" id="forgottenScanReportTable">
            <thead style="background: #2c3e50; color: white;">
                <tr>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">ល.រ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">អត្តលេខ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">ឈ្មោះ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">ភេទ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center;">តួនាទី</th>
                    <th colspan="2" style="text-align: center; background: #2980b9;">ភ្លេចស្កេនដៃ</th>
                    <th rowspan="2" style="vertical-align: middle; text-align: center; background: #c0392b;">សរុប</th>
                </tr>
                <tr>
                    <th style="text-align: center; background: #3498db; font-size: 11px;">ចូល (In)</th>
                    <th style="text-align: center; background: #3498db; font-size: 11px;">ចេញ (Out)</th>
                </tr>
            </thead>
            <tbody>
                <?php
                    $totalIn=0; $totalOut=0; $totalAll=0;
                    if (empty($report_rows)):
                ?>
                    <tr><td colspan="8" style="text-align:center;">មិនមានទិន្នន័យ</td></tr>
                <?php else: ?>
                    <?php $i=1; ?>
                    <?php foreach ($report_rows as $row): ?>
                        <tr>
                            <td style="text-align:center;"><?php echo $i++; ?></td>
                            <td style="text-align:center;"><?php echo htmlspecialchars($row['id']); ?></td>
                            <td style="font-weight:bold;"><?php echo htmlspecialchars($row['name']); ?></td>
                            <td style="text-align:center;"><?php echo htmlspecialchars($row['gender']); ?></td>
                            <td><?php echo htmlspecialchars($row['position']); ?></td>
                            <td style="text-align:center; font-weight:bold; color:#2980b9;"><?php echo $row['forgot_in']; ?></td>
                            <td style="text-align:center; font-weight:bold; color:#2980b9;"><?php echo $row['forgot_out']; ?></td>
                            <td style="text-align:center; font-weight:bold; background:#fdf2f2; color:#c0392b;"><?php echo $row['total']; ?></td>
                        </tr>
                        <?php
                            $totalIn += $row['forgot_in'];
                            $totalOut += $row['forgot_out'];
                            $totalAll += $row['total'];
                        ?>
                    <?php endforeach; ?>
                <?php endif; ?>
            </tbody>
            <tfoot style="background: #f1c40f; font-weight: bold;">
                <tr>
                    <td colspan="5" style="text-align: center;">សរុប</td>
                    <td style="text-align: center;"><?php echo $totalIn; ?></td>
                    <td style="text-align: center;"><?php echo $totalOut; ?></td>
                    <td style="text-align: center;"><?php echo $totalAll; ?></td>
                </tr>
            </tfoot>
        </table>
    </div>

<?php endif; ?>

<?php if ($current_page == 'payroll' && hasPageAccess($mysqli, 'payroll', 'payroll', $admin_id_check)): ?>
    <?php
        // Minimal Payroll UI skeleton
        // Defaults to current month/year
        $pay_month = isset($_GET['pay_month']) ? (int)$_GET['pay_month'] : (int)date('m');
        $pay_year  = isset($_GET['pay_year']) ? (int)$_GET['pay_year'] : (int)date('Y');
    ?>
    <h2><i class="fa-solid fa-money-check-dollar"></i> Payroll</h2>

    <div style="background:#fff; padding:16px; border-radius:10px; box-shadow:0 4px 14px rgba(0,0,0,0.04); margin-bottom:16px;">
        <form id="payrollFilterForm" method="GET" action="admin_attendance.php" style="display:flex; gap:12px; align-items:center; flex-wrap:wrap;">
            <input type="hidden" name="page" value="payroll">
            <label style="display:flex; gap:8px; align-items:center;"><strong>Month</strong>
                <select name="pay_month" class="form-control" style="margin-left:6px;">
                    <?php for ($m=1;$m<=12;$m++): ?>
                        <option value="<?php echo $m; ?>" <?php echo ($m==$pay_month)?'selected':''; ?>><?php echo date('F', mktime(0,0,0,$m,1,2000)); ?></option>
                    <?php endfor; ?>
                </select>
            </label>

            <label style="display:flex; gap:8px; align-items:center;"><strong>Year</strong>
                <select name="pay_year" class="form-control" style="margin-left:6px;">
                    <?php for ($y = date('Y')-3; $y <= date('Y')+1; $y++): ?>
                        <option value="<?php echo $y; ?>" <?php echo ($y==$pay_year)?'selected':''; ?>><?php echo $y; ?></option>
                    <?php endfor; ?>
                </select>
            </label>

            <div style="margin-left:auto; display:flex; gap:8px;">
                <button type="submit" class="btn btn-primary">Apply</button>
                <button type="button" id="runPayrollBtn" class="btn btn-success">Run Payroll</button>
                <button type="button" id="exportPayrollBtn" class="btn btn-outline-secondary">Export</button>
            </div>
        </form>
    </div>

    <div style="background:#fff; padding:16px; border-radius:10px; box-shadow:0 4px 14px rgba(0,0,0,0.04);">
        <h3 style="margin-top:0;">Payroll Preview for <?php echo date('F Y', strtotime($pay_year.'-'.sprintf('%02d',$pay_month).'-01')); ?></h3>
        <p style="color:#6c757d;">This is a skeleton page. Click <strong>Run Payroll</strong> to compute payroll (server implementation required).</p>

        <table class="table" id="payrollTable">
            <thead>
                <tr>
                    <th>#</th>
                    <th>Employee ID</th>
                    <th>Name</th>
                    <th>Basic</th>
                    <th>Allowances</th>
                    <th>Deductions</th>
                    <th>Net Pay</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody>
                <tr><td colspan="8" style="text-align:center; color:#6c757d;">No payroll data calculated yet.</td></tr>
            </tbody>
        </table>
    </div>

    <script>
    (function(){
        document.getElementById('runPayrollBtn').addEventListener('click', function(){
            alert('Run Payroll pressed — server-side implementation not present yet. I can add an AJAX handler (ajax_action=run_payroll) if you want.');
        });
        document.getElementById('exportPayrollBtn').addEventListener('click', function(){
            alert('Export pressed — export implementation not present in this skeleton.');
        });
    })();
    </script>

<?php endif; ?>

           <?php
if ($current_page == 'requests' && hasPageAccess($mysqli, 'requests', 'requests', $admin_id_check)): ?>
    <?php
    $filter_req_status = $_GET['filter_req_status'] ?? 'All';
    $filter_req_type = $_GET['filter_req_type'] ?? 'All';

    $records_per_page = 15;
    $current_p_page = isset($_GET['p']) ? (int)$_GET['p'] : 1;
    $offset = ($current_p_page - 1) * $records_per_page;

    $count_sql = "SELECT COUNT(rl.id) as total
                  FROM `requests_logs` rl
                  JOIN `users` u ON rl.employee_id = u.employee_id
                  WHERE 1=1";
    $count_params = [];
    $count_types = "";

    if ($filter_req_status !== 'All') {
        $count_sql .= " AND rl.`request_status` = ?";
        $count_params[] = $filter_req_status;
        $count_types .= "s";
    }
    if ($filter_req_type !== 'All') {
        $count_sql .= " AND rl.`request_type` = ?";
        $count_params[] = $filter_req_type;
        $count_types .= "s";
    }
    if (!$is_super_admin) {
        $count_sql .= " AND u.created_by_admin_id = ?";
        $count_params[] = $current_admin_id;
        $count_types .= "s";
    }

    $total_records = 0;
    if ($stmt_count = $mysqli->prepare($count_sql)) {
        if (!empty($count_types)) $stmt_count->bind_param($count_types, ...$count_params);
        $stmt_count->execute();
        $total_records = $stmt_count->get_result()->fetch_assoc()['total'];
        $stmt_count->close();
    }

    $total_pages = ceil($total_records / $records_per_page);

    $sql = "SELECT rl.*
            FROM `requests_logs` rl
            JOIN `users` u ON rl.employee_id = u.employee_id
            WHERE 1=1";
    $params = [];
    $types = "";

    if ($filter_req_status !== 'All') {
        $sql .= " AND rl.`request_status` = ?";
        $params[] = $filter_req_status;
        $types .= "s";
    }
    if ($filter_req_type !== 'All') {
        $sql .= " AND rl.`request_type` = ?";
        $params[] = $filter_req_type;
        $types .= "s";
    }
    if (!$is_super_admin) {
        $sql .= " AND u.created_by_admin_id = ?";
        $params[] = $current_admin_id;
        $types .= "s";
    }

    $sql .= " ORDER BY rl.`submitted_at` DESC LIMIT ? OFFSET ?";
    $params[] = $records_per_page;
    $params[] = $offset;
    $types .= "ii";

    $requests_data = [];
    if ($stmt = $mysqli->prepare($sql)) {
        if (!empty($types)) $stmt->bind_param($types, ...$params);
        $stmt->execute();
        $requests_data = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);
        $stmt->close();
    }
    ?>
    <h2><i class="fa-solid fa-file-invoice"></i> គ្រប់គ្រងសំណើបុគ្គលិក</h2>

    <form method="GET" action="admin_attendance.php" style="margin-bottom: 20px; padding: 15px; background: white; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.05);">
        <input type="hidden" name="page" value="requests">
        <div style="display: flex; gap: 15px; align-items: flex-end;">
            <div class="form-group" style="flex: 1;">
                <label for="filter_req_type"><i class="fa-solid fa-folder-open"></i> ប្រភេទសំណើរ</label>
                <select id="filter_req_type" name="filter_req_type" class="form-control" onchange="this.form.submit()">
                    <option value="All" <?php echo ($filter_req_type == 'All') ? 'selected' : ''; ?>>ទាំងអស់</option>
                    <option value="Leave" <?php echo ($filter_req_type == 'Leave') ? 'selected' : ''; ?>>សុំច្បាប់</option>
                    <option value="Overtime" <?php echo ($filter_req_type == 'Overtime') ? 'selected' : ''; ?>>ថែមម៉ោង</option>
                    <option value="Forget-Attendance" <?php echo ($filter_req_type == 'Forget-Attendance') ? 'selected' : ''; ?>>ភ្លេចស្កេន</option>
                    <option value="Late" <?php echo ($filter_req_type == 'Late') ? 'selected' : ''; ?>>មកយឺត</option>
                    <option value="Change-Day-Off" <?php echo ($filter_req_type == 'Change-Day-Off') ? 'selected' : ''; ?>>ប្តូរថ្ងៃសម្រាក</option>
                </select>
            </div>
            <div class="form-group" style="flex: 1;">
                <label for="filter_req_status"><i class="fa-solid fa-tags"></i> ស្ថានភាព</label>
                <select id="filter_req_status" name="filter_req_status" class="form-control" onchange="this.form.submit()">
                    <option value="All" <?php echo ($filter_req_status == 'All') ? 'selected' : ''; ?>>ទាំងអស់</option>
                    <option value="Pending" <?php echo ($filter_req_status == 'Pending') ? 'selected' : ''; ?>>កំពុងរង់ចាំ</option>
                    <option value="Approved" <?php echo ($filter_req_status == 'Approved') ? 'selected' : ''; ?>>បានយល់ព្រម</option>
                    <option value="Rejected" <?php echo ($filter_req_status == 'Rejected') ? 'selected' : ''; ?>>បានបដិសេធ</option>
                </select>
            </div>
        </div>
    </form>

    <h3 style="margin-top: 40px;"><i class="fa-solid fa-list-ul"></i> បញ្ជីសំណើទាំងអស់</h3>

    <table class="table">
        <thead>
            <tr>
                <th>ID</th>
                <th><i class="fa-solid fa-user"></i> ឈ្មោះបុគ្គលិក</th>
                <th><i class="fa-solid fa-folder"></i> ប្រភេទ</th>
                <th><i class="fa-solid fa-tag"></i> ស្ថានភាព</th>
                <th><i class="fa-solid fa-clock"></i> ថ្ងៃដាក់ស្នើ</th>
                <th><i class="fa-solid fa-calendar-day"></i> ថ្ងៃព្រឹត្តិការណ៍</th>
                <th><i class="fa-solid fa-sliders"></i> សកម្មភាព</th>
            </tr>
        </thead>
        <tbody>
            <?php if (empty($requests_data)): ?>
                <tr><td colspan="7" style="text-align: center; font-style: italic;">មិនមានទិន្នន័យសំណើដែលត្រូវនឹងលក្ខខណ្ឌស្វែងរកទេ។</td></tr>
            <?php else: ?>
                <?php foreach ($requests_data as $req): ?>
                    <tr>
                        <td><?php echo htmlspecialchars($req['id']); ?></td>
                        <td><?php echo htmlspecialchars($req['name']); ?><br><small style="color: #7f8c8d;"><?php echo htmlspecialchars($req['employee_id']); ?></small></td>
                        <td><?php echo htmlspecialchars(str_replace('-', ' ', $req['request_type'])); ?></td>
                        <td>
                            <?php
                            $status_class = 'status-' . strtolower($req['request_status']);
                            echo "<span class='status-badge {$status_class}'>" . htmlspecialchars($req['request_status']) . "</span>";
                            ?>
                        </td>
                        <td><?php echo date('d/m/Y h:i A', strtotime($req['submitted_at'])); ?></td>
                        <td><?php echo $req['event_date'] ? date('d/m/Y', strtotime($req['event_date'])) : 'N/A'; ?></td>
                        <td>
                            <?php $js_data = htmlspecialchars(json_encode($req), ENT_QUOTES, 'UTF-8'); ?>
                            <button class="btn btn-primary btn-sm" onclick="showRequestDetailsModal(<?php echo $js_data; ?>)">
                                <i class="fa-solid fa-eye"></i> មើលលម្អិត
                            </button>
                        </td>
                    </tr>
                <?php endforeach; ?>
            <?php endif; ?>
        </tbody>
    </table>





    <?php
    if ($total_pages > 1):
        $query_params = [
            'page' => 'requests',
            'filter_req_status' => $filter_req_status,
            'filter_req_type' => $filter_req_type
        ];
    ?>
    <nav>
        <ul class="pagination">
            <li class="<?php if($current_p_page <= 1){ echo 'disabled'; } ?>">
                <a href="<?php if($current_p_page > 1){ echo '?' . http_build_query(array_merge($query_params, ['p' => $current_p_page - 1])); } else { echo '#'; } ?>">Previous</a>
            </li>

            <?php for ($i = 1; $i <= $total_pages; $i++): ?>
            <li class="<?php if($current_p_page == $i) {echo 'active'; } ?>">
                <a href="?<?php echo http_build_query(array_merge($query_params, ['p' => $i])); ?>"><?php echo $i; ?></a>
            </li>
            <?php endfor; ?>

            <li class="<?php if($current_p_page >= $total_pages) { echo 'disabled'; } ?>">
                <a href="<?php if($current_p_page < $total_pages) { echo '?' . http_build_query(array_merge($query_params, ['p' => $current_p_page + 1])); } else { echo '#'; } ?>">Next</a>
            </li>
        </ul>
    </nav>
    <?php endif; ?>
<?php endif; ?>

            <?php if ($current_page == 'notifications' && hasPageAccess($mysqli, 'notifications', 'send_notifications', $admin_id_check)): ?>
                <h2><i class="fa-solid fa-bell"></i> ផ្ញើការជូនដំណឹង</h2>

                <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                    <h3><i class="fa-solid fa-paper-plane"></i> ផ្ញើការជូនដំណឹងទៅអ្នកប្រើប្រាស់</h3>
                    <form id="sendNotificationForm" class="ajax-form">
                        <input type="hidden" name="ajax_action" value="send_notification">

                        <div class="form-group">
                            <label><i class="fa-solid fa-users"></i> ជ្រើសរើសអ្នកទទួល:</label>
                            <select name="recipient_type" id="recipient_type" class="form-control" required>
                                <option value="all">អ្នកប្រើប្រាស់ទាំងអស់</option>
                                <option value="specific">អ្នកប្រើប្រាស់ជាក់លាក់</option>
                                <option value="group">ក្រុមជំនាញ</option>
                            </select>
                        </div>

                        <div class="form-group" id="specific_users_group" style="display: none;">
                            <label><i class="fa-solid fa-user-check"></i> ជ្រើសរើសអ្នកប្រើប្រាស់:</label>
                            <select name="specific_users[]" multiple class="form-control" style="height: 150px;">
                                <?php
                                $users_query = $mysqli->prepare("SELECT employee_id, name FROM users WHERE created_by_admin_id = ? ORDER BY name ASC");
                                $users_query->bind_param("s", $current_admin_id);
                                $users_query->execute();
                                $users_result = $users_query->get_result();
                                while ($user = $users_result->fetch_assoc()) {
                                    echo '<option value="' . htmlspecialchars($user['employee_id']) . '">' . htmlspecialchars($user['name']) . ' (' . htmlspecialchars($user['employee_id']) . ')</option>';
                                }
                                $users_query->close();
                                ?>
                            </select>
                            <small class="form-text text-muted">ចុច Ctrl ដើម្បីជ្រើសរើសច្រើន</small>
                        </div>

                        <div class="form-group" id="group_selection_group" style="display: none;">
                            <label><i class="fa-solid fa-layer-group"></i> ជ្រើសរើសក្រុម:</label>
                            <select name="group_id" class="form-control">
                                <option value="">— ជ្រើសរើសក្រុម —</option>
                                <?php
                                ensure_user_groups_table($mysqli);
                                $groups_query = $mysqli->prepare("SELECT id, group_name FROM user_skill_groups WHERE admin_id = ? ORDER BY group_name ASC");
                                $groups_query->bind_param("s", $current_admin_id);
                                $groups_query->execute();
                                $groups_result = $groups_query->get_result();
                                while ($group = $groups_result->fetch_assoc()) {
                                    echo '<option value="' . (int)$group['id'] . '">' . htmlspecialchars($group['group_name']) . '</option>';
                                }
                                $groups_query->close();
                                ?>
                            </select>
                        </div>

                        <div class="form-group">
                            <label><i class="fa-solid fa-heading"></i> ប្រធានបទ:</label>
                            <input type="text" name="notification_title" class="form-control" required placeholder="ឧ. ការជូនដំណឹងសំខាន់">
                        </div>

                        <div class="form-group">
                            <label><i class="fa-solid fa-message"></i> ខ្លឹមសារ:</label>
                            <textarea name="notification_message" class="form-control" rows="5" required placeholder="សរសេរខ្លឹមសារការជូនដំណឹងនៅទីនេះ..."></textarea>
                        </div>

                        <div class="form-group">
                            <label><i class="fa-solid fa-calendar"></i> កាលបរិច្ឆេទផុតកំណត់ (Optional):</label>
                            <input type="datetime-local" name="expiry_date" class="form-control">
                        </div>

                        <button type="submit" class="btn btn-primary"><i class="fa-solid fa-paper-plane"></i> ផ្ញើការជូនដំណឹង</button>
                    </form>
                </div>

                <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05);">
                    <h3><i class="fa-solid fa-history"></i> ប្រវត្តិការជូនដំណឹង</h3>
                    <table class="table">
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>ប្រធានបទ</th>
                                <th>អ្នកទទួល</th>
                                <th>កាលបរិច្ឆេទផ្ញើ</th>
                                <th>ស្ថានភាព</th>
                            </tr>
                        </thead>
                        <tbody id="notificationsHistory">
                            <tr><td colspan="5" style="text-align: center;">កំពុងទាញយកទិន្នន័យ...</td></tr>
                        </tbody>
                    </table>
                </div>

                <script>
                $(document).ready(function() {
                    // Toggle recipient selection
                    $('#recipient_type').change(function() {
                        var type = $(this).val();
                        $('#specific_users_group').hide();
                        $('#group_selection_group').hide();
                        if (type === 'specific') {
                            $('#specific_users_group').show();
                        } else if (type === 'group') {
                            $('#group_selection_group').show();
                        }
                    });

                    // Load notifications history
                    loadNotificationsHistory();
                });

                function loadNotificationsHistory() {
                    $.ajax({
                        url: '',
                        type: 'POST',
                        data: { ajax_action: 'get_notifications_history' },
                        success: function(response) {
                            if (response.status === 'success') {
                                var html = '';
                                if (response.data.length === 0) {
                                    html = '<tr><td colspan="5" style="text-align: center;">មិនមានប្រវត្តិការជូនដំណឹងទេ។</td></tr>';
                                } else {
                                    response.data.forEach(function(notification) {
                                        html += '<tr>' +
                                            '<td>' + notification.id + '</td>' +
                                            '<td>' + notification.title + '</td>' +
                                            '<td>' + notification.recipient_info + '</td>' +
                                            '<td>' + notification.sent_at + '</td>' +
                                            '<td><span class="status-badge status-' + notification.status.toLowerCase() + '">' + notification.status + '</span></td>' +
                                            '</tr>';
                                    });
                                }
                                $('#notificationsHistory').html(html);
                            }
                        }
                    });
                }
                </script>
            <?php endif; ?>

            <?php if ($current_page == 'users'):
                $user_action = $_GET['action'] ?? 'list_users';
            ?>
                <?php if ($is_super_admin && ($user_action == 'edit_admin_access' || $user_action == 'edit_admin_subscription') && isset($_GET['id'])):
                    $target_admin_id = $_GET['id'];
                    $target_admin_info = $mysqli->query("SELECT * FROM users WHERE employee_id = '{$mysqli->real_escape_string($target_admin_id)}' AND user_role = 'Admin'")->fetch_assoc();

                    if (!$target_admin_info) {
                        $error = "មិនមានគណនី Admin ID នេះទេ។";
                    } else {
                        $admin_name_display = htmlspecialchars($target_admin_info['name']);
                        $is_super_admin_target = (bool)$target_admin_info['is_super_admin'];
                    }

                    if ($user_action == 'edit_admin_access'):
                        $allowed_pages_query = $mysqli->query("SELECT page_key, action_key FROM page_access_settings WHERE employee_id = '{$mysqli->real_escape_string($target_admin_id)}'");
                        $allowed_action_keys = [];
                        if ($allowed_pages_query) {
                            while ($row = $allowed_pages_query->fetch_assoc()) {
                                $allowed_action_keys[] = $row['action_key'];
                            }
                        }
                    ?>
                        <h2><i class="fa-solid fa-sitemap"></i> កំណត់ Page/Action Access សម្រាប់: **<?php echo $admin_name_display; ?>**</h2>
                        <p class="alert alert-info">Admin ID: **<?php echo htmlspecialchars($target_admin_id); ?>** | តួនាទី: **<?php echo $is_super_admin_target ? 'Super Admin' : 'Admin ធម្មតា'; ?>**</p>

                        <a href="?page=users&action=list_users#user-row-<?php echo htmlspecialchars($target_admin_id); ?>" class="btn btn-primary" style="margin-bottom: 20px;"><i class="fa-solid fa-arrow-left"></i> ត្រឡប់ទៅបញ្ជី Admin</a>

                        <?php if ($is_super_admin_target): ?>
                            <div class="alert alert-danger">**Super Admin** គឺមានសិទ្ធិចូលប្រើគ្រប់ទំព័រទាំងអស់។ ការកំណត់នេះមិនអាចកែប្រែបានទេ។</div>
                        <?php else: ?>
                            <form id="pageAccessForm" class="ajax-form">
                                <input type="hidden" name="ajax_action" value="save_admin_page_access">
                                <input type="hidden" name="target_admin_id" value="<?php echo htmlspecialchars($target_admin_id); ?>">

                                <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05);">
                                    <label><i class="fa-solid fa-list-check"></i> ជ្រើសរើស **Actions/Subpages** ដែល Admin **<?php echo $admin_name_display; ?>** អាចឃើញ:</label>

                                    <?php
                                    foreach ($admin_pages_list as $page_key => $actions):
                                        if ($page_key === 'dashboard') continue;

                                        $has_allowed_action = false;
                                        foreach ($actions as $action_key => $name) {
                                            if (in_array($action_key, $allowed_action_keys)) {
                                                $has_allowed_action = true;
                                                break;
                                            }
                                        }
                                    ?>
                                        <details <?php echo $has_allowed_action ? 'open' : ''; ?> style="margin-top: 15px;">
                                            <summary style="background-color: #ecf0f1; border-left: 5px solid var(--primary-color); padding-left: 10px; font-weight: 700;">
                                                <i class="fa-solid fa-folder"></i> <?php echo htmlspecialchars(ucfirst($page_key)); ?>
                                            </summary>
                                            <div class="checkbox-container subpage-access" style="max-height: none; background: white; border-left: none;">
                                                <?php foreach ($actions as $action_key => $name):
                                                    if ($page_key === 'users' && $action_key === 'create_admin') continue;

                                                    $is_checked = in_array($action_key, $allowed_action_keys);
                                                ?>
                                                    <div class="checkbox-item" style="padding-left: 15px; border-left: 3px solid #ddd; margin-left: 10px;">
                                                        <input type="checkbox" name="allowed_actions[]" value="<?php echo htmlspecialchars($action_key); ?>" id="action_<?php echo htmlspecialchars($action_key); ?>" <?php echo $is_checked ? 'checked' : ''; ?>>
                                                        <label for="action_<?php echo htmlspecialchars($action_key); ?>"><?php echo htmlspecialchars($name); ?></label>
                                                    </div>
                                                <?php endforeach; ?>
                                            </div>
                                        </details>
                                    <?php endforeach; ?>

                                    <div class="checkbox-item" style="flex: 1 1 45%; color: #2ecc71; margin-top: 15px;">
                                        <i class="fa-solid fa-circle-check"></i> **Dashboard** (Allowed by Default)
                                    </div>

                                    <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 20px;"><i class="fa-solid fa-save"></i> រក្សាទុក Page/Action Access</button>
                                </div>
                            </form>
                        <?php endif; ?>

                    <?php elseif ($user_action == 'edit_admin_subscription'):
                        $sub_info = $target_admin_info;
                        $expiry_input_value = '';
                        if (!empty($sub_info['expiry_datetime'])) {
                            $expiry_input_value = date('Y-m-d\TH:i', strtotime($sub_info['expiry_datetime']));
                        }
                    ?>
                        <h2><i class="fa-solid fa-calendar-check"></i> កំណត់ Subscription សម្រាប់: **<?php echo $admin_name_display; ?>**</h2>
                        <p class="alert alert-info">Admin ID: **<?php echo htmlspecialchars($target_admin_id); ?>** | តួនាទី: **<?php echo $is_super_admin_target ? 'Super Admin' : 'Admin ធម្មតា'; ?>**</p>
                        <a href="?page=users&action=list_users#user-row-<?php echo htmlspecialchars($target_admin_id); ?>" class="btn btn-primary" style="margin-bottom: 20px;"><i class="fa-solid fa-arrow-left"></i> ត្រឡប់ទៅបញ្ជី Admin</a>

                        <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
							<h3 style="margin-top: 0; color: var(--primary-color);"><i class="fa-solid fa-calendar-check"></i> កំណត់ Subscription Access</h3>

							<form id="updateSubscriptionForm" class="ajax-form">
								<input type="hidden" name="ajax_action" value="update_admin_subscription_settings">
                                <input type="hidden" name="target_admin_id" value="<?php echo htmlspecialchars($target_admin_id); ?>">

								<div class="form-group">
									<label for="access_mode"><i class="fa-solid fa-toggle-on"></i> របៀបចូលប្រើប្រាស់:</label>
									<select name="access_mode" id="access_mode" class="form-control" onchange="toggleExpiryField(this.value)">
										<option value="Free" <?php echo $sub_info['access_mode'] == 'Free' ? 'selected' : ''; ?>>1. ឥតគិតថ្លៃ (Free Access)</option>
										<option value="Paid" <?php echo $sub_info['access_mode'] == 'Paid' ? 'selected' : ''; ?>>2. មានកំណត់ថ្ងៃ (Paid/Subscription)</option>
										<option value="Expired" <?php echo $sub_info['access_mode'] == 'Expired' ? 'selected' : ''; ?>>3. ផុតកំណត់ (Expired)</option>
									</select>
								</div>

								<div class="form-group" id="expiryDateGroup" style="display: <?php echo $sub_info['access_mode'] == 'Paid' ? 'block' : 'none'; ?>;">
									<label for="expiry_datetime"><i class="fa-solid fa-calendar-alt"></i> ថ្ងៃ និងម៉ោងផុតកំណត់:</label>
									<input type="datetime-local" name="expiry_datetime" id="expiry_datetime" class="form-control" value="<?php echo htmlspecialchars($expiry_input_value); ?>">
								</div>

								<div class="form-group">
									<label for="telegram_chat_id"><i class="fa-brands fa-telegram"></i> Telegram Chat ID (សម្រាប់ជូនដំណឹងជិតផុតកំណត់):</label>
									<input type="text" name="telegram_chat_id" id="telegram_chat_id" class="form-control" placeholder="បញ្ចូល Chat ID របស់អ្នក" value="<?php echo htmlspecialchars($sub_info['telegram_chat_id'] ?? ''); ?>">
									<small style="display: block; margin-top: 5px; color: #7f8c8d;">**ចំណាំ:** ត្រូវបញ្ចូល Bot Token ក្នុងកូដ PHP ផងដែរដើម្បីឱ្យមុខងារជូនដំណឹងដំណើរការ។</small>
								</div>

								<button type="submit" class="btn btn-primary"><i class="fa-solid fa-save"></i> រក្សាទុកការកំណត់</button>
							</form>

							<hr>

							<div id="subscription-renewal-area">
								<h4 style="margin-top: 0;"><i class="fa-solid fa-repeat"></i> បន្តថ្ងៃប្រើប្រាស់</h4>
								<p>បន្តថ្ងៃប្រើប្រាស់បន្ថែម **365 ថ្ងៃ** (1 ឆ្នាំ) ទៅលើថ្ងៃផុតកំណត់ដែលមានស្រាប់ ឬពីថ្ងៃនេះប្រសិនបើផុតកំណត់ហើយ។</p>
								<form id="extendSubscriptionForm" class="ajax-form">
									<input type="hidden" name="ajax_action" value="extend_admin_subscription">
									<input type="hidden" name="target_admin_id" value="<?php echo htmlspecialchars($target_admin_id); ?>">
									<input type="hidden" name="days_to_add" value="365">
									<button type="submit" class="btn btn-danger"><i class="fa-solid fa-circle-plus"></i> បន្តប្រើប្រាស់ 1 ឆ្នាំ</button>
								</form>
							</div>
						</div>

                    <?php endif; ?>


                <?php elseif ($user_action == 'edit_rules' && canManageTimeRules($mysqli, $admin_id_check) && isset($_GET['id'])):
                    $employee_id = $_GET['id'];
                    $user_info_sql = "SELECT name FROM users WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE)";
                    $user_stmt = $mysqli->prepare($user_info_sql);
                    $user_stmt->bind_param("ssi", $employee_id, $current_admin_id, $is_super_admin);
                    $user_stmt->execute();
                    $user_info_query = $user_stmt->get_result();
                    if (!$user_info_query || $user_info_query->num_rows == 0) {
                        $error = "មិនមានបុគ្គលិក ID នេះទេ។";
                        $user_info = ['name' => 'N/A'];
                    } else {
                        $user_info = $user_info_query->fetch_assoc();
                    }
                    $user_stmt->close();

                    $rules_sql = "SELECT * FROM attendance_rules WHERE employee_id = ? AND (created_by_admin_id = ? OR ? = TRUE) ORDER BY type DESC, start_time ASC";
                    $rules_stmt = $mysqli->prepare($rules_sql);
                    $rules_stmt->bind_param("ssi", $employee_id, $current_admin_id, $is_super_admin);
                    $rules_stmt->execute();
                    $current_rules = $rules_stmt->get_result()->fetch_all(MYSQLI_ASSOC);
                    $rules_stmt->close();

                    $ci_rules = array_filter($current_rules, fn($r) => $r['type'] == 'checkin');
                    $co_rules = array_filter($current_rules, fn($r) => $r['type'] == 'checkout');
                ?>
                    <div class="rules-editor-wrapper" style="max-width: 1100px; margin: 0 auto; animation: fadeInUp 0.4s ease-out;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 25px;">
                            <h2 style="margin:0; font-family: 'Kantumruy Pro', sans-serif; color: #1a202c;">
                                <i class="fa-solid fa-clock-rotate-left" style="color: #3182ce; margin-right: 10px;"></i>
                                កែសម្រួលច្បាប់ម៉ោង: <span style="color: #2b6cb0;"><?php echo htmlspecialchars($user_info['name']); ?></span>
                            </h2>
                            <a href="?page=users&action=list_users#user-row-<?php echo htmlspecialchars($employee_id); ?>" class="btn btn-outline-secondary" style="border-radius: 10px;">
                                <i class="fa-solid fa-arrow-left"></i> ត្រឡប់ទៅបញ្ជី
                            </a>
                        </div>

                        <!-- Quick Actions Card: Copy Feature -->
                        <div class="copy-feature-card" style="background: linear-gradient(135deg, #f6f8fa 0%, #edf2f7 100%); padding: 20px; border-radius: 16px; margin-bottom: 25px; border: 1px solid #e2e8f0; display: flex; align-items: center; gap: 20px; box-shadow: 0 4px 15px rgba(0,0,0,0.03);">
                            <div style="background: #3182ce; color: white; width: 45px; height: 45px; border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; flex-shrink: 0;">
                                <i class="fa-solid fa-copy"></i>
                            </div>
                            <div style="flex-grow: 1;">
                                <h4 style="margin: 0 0 5px 0; font-size: 1rem; color: #2d3748;">ចម្លងច្បាប់ម៉ោងពីអ្នកប្រើប្រាស់ផ្សេង (Copy Rules)</h4>
                                <p style="margin: 0; font-size: 0.85rem; color: #718096;">អ្នកអាចជ្រើសរើសបុគ្គលិកណាម្នាក់ ដើម្បីចម្លងច្បាប់ម៉ោងមកដាក់ក្នុងគណនីនេះភ្លាមៗ។</p>
                            </div>
                            <div style="display: flex; gap: 10px; min-width: 450px;">
                                <select id="copyFromUserSelect" class="form-control" style="border-radius: 10px; border: 1px solid #cbd5e0;">
                                    <option value="">-- ជ្រើសរើសបុគ្គលិកចម្លង --</option>
                                    <?php
                                        $other_users_sql = "SELECT employee_id, name FROM users WHERE user_role = 'User' AND employee_id != ? AND (created_by_admin_id = ? OR ? = TRUE) ORDER BY name ASC";
                                        if ($ou_stmt = $mysqli->prepare($other_users_sql)) {
                                            $ou_stmt->bind_param('ssi', $employee_id, $current_admin_id, $is_super_admin);
                                            $ou_stmt->execute();
                                            $ou_res = $ou_stmt->get_result();
                                            while ($ou = $ou_res->fetch_assoc()) {
                                                echo '<option value="' . htmlspecialchars($ou['employee_id']) . '">' . htmlspecialchars($ou['name']) . ' (' . htmlspecialchars($ou['employee_id']) . ')</option>';
                                            }
                                            $ou_stmt->close();
                                        }
                                    ?>
                                </select>
                                <button type="button" id="copyFromUserBtn" class="btn btn-primary" style="padding: 0 25px; border-radius: 10px; font-weight: 600; background: #3182ce;">
                                    <i class="fa-solid fa-file-import"></i> ចម្លងម៉ោង
                                </button>
                            </div>
                        </div>

                        <form id="timeRulesForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="save_time_rules">
                            <input type="hidden" name="rule_employee_id" value="<?php echo htmlspecialchars($employee_id); ?>">
                            <input type="hidden" id="rulesJsonInput" name="rules_json">

                            <div style="display: grid; grid-template-columns: 1fr; gap: 30px;">
                                <!-- Check-in Section -->
                                <div class="rules-section-card" style="background: white; padding: 25px; border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 1px solid #edf2f7;">
                                    <h3 style="color: #3182ce; margin-top: 0; display: flex; align-items: center; gap: 10px; border-bottom: 2px solid #ebf8ff; padding-bottom: 15px; margin-bottom: 20px;">
                                        <i class="fa-solid fa-right-to-bracket"></i> ម៉ោងចូលធ្វើការ (Check-in)
                                    </h3>
                                    <div id="checkinRulesContainer" style="display: flex; flex-direction: column; gap: 12px;">
                                        <?php foreach ($ci_rules as $rule): ?>
                                        <div class="time-rule-row" data-type="checkin">
                                            <label><i class="fa-solid fa-play"></i> ចាប់ពី</label>
                                            <input type="time" class="form-control rule-start" value="<?php echo htmlspecialchars($rule['start_time']); ?>" step="1">
                                            <label><i class="fa-solid fa-stop"></i> ដល់</label>
                                            <input type="time" class="form-control rule-end" value="<?php echo htmlspecialchars($rule['end_time']); ?>" step="1">
                                            <label><i class="fa-solid fa-circle-info"></i> ស្ថានភាព</label>
                                            <select class="form-control rule-status">
                                                <option value="Good" <?php echo $rule['status'] == 'Good' ? 'selected' : ''; ?>>✅ Good</option>
                                                <option value="Late" <?php echo $rule['status'] == 'Late' ? 'selected' : ''; ?>>⚠️ Late</option>
                                                <option value="Absent" <?php echo $rule['status'] == 'Absent' ? 'selected' : ''; ?>>❌ Absent</option>
                                            </select>
                                            <button type="button" class="btn btn-danger remove-rule" onclick="this.parentNode.remove()"><i class="fa-solid fa-trash"></i></button>
                                        </div>
                                        <?php endforeach; ?>
                                    </div>
                                    <button type="button" class="btn btn-outline-primary" onclick="addTimeRule('checkin')" style="margin-top: 20px; width: 100%; border-style: dashed; padding: 12px; font-weight: 600;">
                                        <i class="fa-solid fa-plus-circle"></i> បន្ថែមចន្លោះម៉ោងចូល (Add Check-in Range)
                                    </button>
                                </div>

                                <!-- Check-out Section -->
                                <div class="rules-section-card" style="background: white; padding: 25px; border-radius: 20px; box-shadow: 0 10px 25px rgba(0,0,0,0.05); border: 1px solid #edf2f7;">
                                    <h3 style="color: #2f855a; margin-top: 0; display: flex; align-items: center; gap: 10px; border-bottom: 2px solid #f0fff4; padding-bottom: 15px; margin-bottom: 20px;">
                                        <i class="fa-solid fa-right-from-bracket"></i> ម៉ោងចេញពីការងារ (Check-out)
                                    </h3>
                                    <div id="checkoutRulesContainer" style="display: flex; flex-direction: column; gap: 12px;">
                                        <?php foreach ($co_rules as $rule): ?>
                                        <div class="time-rule-row" data-type="checkout">
                                            <label><i class="fa-solid fa-play"></i> ចាប់ពី</label>
                                            <input type="time" class="form-control rule-start" value="<?php echo htmlspecialchars($rule['start_time']); ?>" step="1">
                                            <label><i class="fa-solid fa-stop"></i> ដល់</label>
                                            <input type="time" class="form-control rule-end" value="<?php echo htmlspecialchars($rule['end_time']); ?>" step="1">
                                            <label><i class="fa-solid fa-circle-info"></i> ស្ថានភាព</label>
                                            <select class="form-control rule-status">
                                                <option value="Good" <?php echo $rule['status'] == 'Good' ? 'selected' : ''; ?>>✅ Good</option>
                                                <option value="Late" <?php echo $rule['status'] == 'Late' ? 'selected' : ''; ?>>⚠️ Late</option>
                                                <option value="Absent" <?php echo $rule['status'] == 'Absent' ? 'selected' : ''; ?>>❌ Absent</option>
                                            </select>
                                            <button type="button" class="btn btn-danger remove-rule" onclick="this.parentNode.remove()"><i class="fa-solid fa-trash"></i></button>
                                        </div>
                                        <?php endforeach; ?>
                                    </div>
                                    <button type="button" class="btn btn-outline-success" onclick="addTimeRule('checkout')" style="margin-top: 20px; width: 100%; border-style: dashed; padding: 12px; font-weight: 600;">
                                        <i class="fa-solid fa-plus-circle"></i> បន្ថែមចន្លោះម៉ោងចេញ (Add Check-out Range)
                                    </button>
                                </div>
                            </div>

                            <div style="margin-top: 40px; text-align: center;">
                                <button type="submit" class="btn btn-primary" style="padding: 15px 40px; font-size: 1.1rem; border-radius: 15px; font-weight: 700; background: linear-gradient(135deg, #3182ce 0%, #2b6cb0 100%); box-shadow: 0 10px 20px rgba(49,130,206,0.3); width: 100%; max-width: 400px; transition: all 0.3s;">
                                    <i class="fa-solid fa-cloud-arrow-up"></i> រក្សាទុកច្បាប់ម៉ោងទាំងអស់
                                </button>
                                <p style="margin-top: 15px; font-size: 0.9rem; color: #718096; font-style: italic;">
                                    <i class="fa-solid fa-circle-info"></i> ប្រសិនបើបុគ្គលិក Check-in/out ធ្លាក់ចូលក្នុងចន្លោះម៉ោងណា ពួកគេនឹងទទួលបានស្ថានភាពនោះដោយស្វ័យប្រវត្តិ។
                                </p>
                            </div>
                        </form>
                    </div>
                <?php endif; ?>


                <?php if ($user_action === 'create_user' && hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check)): ?>
                    <h2><i class="fa-solid fa-user-plus"></i> បង្កើតអ្នកប្រើប្រាស់ថ្មី ឬ Sub User</h2>
                    <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05);">
                        <form id="addUserForm" class="ajax-form" enctype="multipart/form-data" onsubmit="return prepareUserFormSubmission(this)">
                            <input type="hidden" name="ajax_action" id="user_form_action" value="add_user">
                            <!-- User Type Selector -->
                            <div class="form-group">
                                <label><i class="fa-solid fa-layer-group"></i> ប្រភេទអ្នកប្រើប្រាស់ (User Type):</label>
                                <select id="user_type_select" name="user_type" class="form-control">
                                    <option value="normal" selected>Normal User (វត្តមាន)</option>
                                    <option value="sub">Sub User (UI Scoped)</option>
                                </select>
                            </div>
                            <!-- Normal User Fields -->
                            <div id="normalUserFields">
                                <div class="form-group"><label><i class="fa-solid fa-id-card-clip"></i> ID:</label><input type="text" name="new_id" class="form-control" required></div>
                                <div class="form-group"><label><i class="fa-solid fa-user"></i> ឈ្មោះ:</label><input type="text" name="new_name" class="form-control" required></div>
                                <!-- Kept form minimal for scan users: only avatar extra field is shown -->
                                <div class="form-group"><label><i class="fa-solid fa-image"></i> រូបប្រវត្តិ (Avatar):</label><input type="file" name="avatar_file" accept="image/*" class="form-control"></div>
                            </div>
                            <!-- Sub User Fields (hidden by default) -->
                            <div id="subUserFields" style="display:none; border:1px dashed #ccc; padding:12px; border-radius:6px; margin-top:10px;">
                                <div class="form-group"><label><i class="fa-solid fa-user-tag"></i> Sub ID:</label><input type="text" name="sub_id" class="form-control" autocomplete="off"></div>
                                <div class="form-group"><label><i class="fa-solid fa-signature"></i> Sub Name:</label><input type="text" name="sub_name" class="form-control" autocomplete="off"></div>
                                <div class="form-group"><label><i class="fa-solid fa-key"></i> Sub Password:</label><input type="password" name="sub_password" class="form-control" autocomplete="new-password"></div>
                                <input type="hidden" name="parent_employee_id" value="<?php echo htmlspecialchars($current_admin_id); ?>">
                                <div class="form-group">
                                    <label><i class="fa-solid fa-eye"></i> UI Permissions:</label>
                                    <div style="display:grid; grid-template-columns:repeat(auto-fill,minmax(160px,1fr)); gap:6px;">
                                        <?php
                                        // Provide a small set of UI permission keys. If a broader list exists you can extend here.
                                        $sub_perm_options = ['users_list'=>'User List','locations'=>'Locations','requests'=>'Requests','reports'=>'Reports','notifications'=>'Notifications'];
                                        foreach ($sub_perm_options as $pk => $pl) {
                                            echo '<label style="font-weight:normal; display:flex; gap:4px; align-items:center;"><input type="checkbox" class="sub-ui-perm" value="'.htmlspecialchars($pk).'"> '.htmlspecialchars($pl).'</label>';
                                        }
                                        ?>
                                    </div>
                                </div>
                                <input type="hidden" name="ui_permissions_json" id="ui_permissions_json" value="[]">
                            </div>
                            <?php
                                // Load groups for assignment
                                ensure_user_groups_table($mysqli);
                                $grp_stmt = $mysqli->prepare("SELECT id, group_name FROM user_skill_groups WHERE admin_id = ? ORDER BY sort_order ASC, group_name ASC");
                                $grp_stmt->bind_param("s", $current_admin_id); $grp_stmt->execute(); $grp_res = $grp_stmt->get_result();
                                if ($grp_res && $grp_res->num_rows > 0) {
                                    echo '<div class="form-group"><label><i class="fa-solid fa-layer-group"></i> ក្រុមជំនាញ (Skill Group):</label><select name="group_id" class="form-control"><option value="">— គ្មាន —</option>';
                                    while($gr = $grp_res->fetch_assoc()) { echo '<option value="'.(int)$gr['id'].'">'.htmlspecialchars($gr['group_name']).'</option>'; }
                                    echo '</select></div>';
                                }
                                $grp_stmt->close();
                            ?>

                            <?php
                                // NEW: Dynamically generate form fields
                                $fields_stmt = $mysqli->prepare("SELECT field_key, field_label, field_type, is_required FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC");
                                $fields_stmt->bind_param("s", $current_admin_id);
                                $fields_stmt->execute();
                                $custom_fields = $fields_stmt->get_result();
                                if ($custom_fields) {
                                    while($field = $custom_fields->fetch_assoc()) {
                                        $required_attr = $field['is_required'] ? 'required' : '';
                                        $field_key = htmlspecialchars($field['field_key']);
                                        $field_label = htmlspecialchars($field['field_label']);
                                        $field_type = htmlspecialchars($field['field_type']);
                                        echo "<div class='form-group'>";
                                        echo "<label>{$field_label}:</label>";
                                        echo "<input type='{$field_type}' name='custom[{$field_key}]' class='form-control' {$required_attr}>";
                                        echo "</div>";
                                    }
                                }
                                $fields_stmt->close();
                            ?>


                            <button type="submit" class="btn btn-primary" id="userFormSubmitBtn"><i class="fa-solid fa-circle-plus"></i> <span id="userFormSubmitLabel">បង្កើត User</span></button>
                        </form>
                        <script>
                        /* Removed misplaced tab script (moved to correct scope in manage_app_scan section) */
                        </script>
                    </div>
                    <script>
                        function prepareUserFormSubmission(f){
                            var type = document.getElementById('user_type_select').value;
                            if(type === 'sub'){
                                // Collect permissions
                                var perms = [];
                                document.querySelectorAll('#subUserFields .sub-ui-perm:checked').forEach(function(cb){perms.push(cb.value);});
                                document.getElementById('ui_permissions_json').value = JSON.stringify(perms);
                                // Basic validation
                                var sid = f.querySelector('input[name="sub_id"]').value.trim();
                                var sname = f.querySelector('input[name="sub_name"]').value.trim();
                                var spass = f.querySelector('input[name="sub_password"]').value.trim();
                                if(!sid || !sname || !spass){
                                    alert('សូមបំពេញ Sub ID / Name / Password');
                                    return false;
                                }
                            }
                            return true;
                        }
                        (function(){
                            var sel = document.getElementById('user_type_select');
                            var normalBox = document.getElementById('normalUserFields');
                            var subBox = document.getElementById('subUserFields');
                            var actionInput = document.getElementById('user_form_action');
                            var submitLabel = document.getElementById('userFormSubmitLabel');
                            function toggleRequired(container, on){
                                container.querySelectorAll('input, select, textarea').forEach(function(el){
                                    if(on){ el.setAttribute('required', el.getAttribute('data-was-required') === '1' || el.required ? 'required' : ''); }
                                    else {
                                        if(el.required) el.setAttribute('data-was-required','1');
                                        el.removeAttribute('required');
                                    }
                                });
                            }
                            sel.addEventListener('change', function(){
                                if(sel.value === 'sub'){
                                    normalBox.style.display='none';
                                    subBox.style.display='block';
                                    actionInput.value='add_sub_user';
                                    submitLabel.textContent='បង្កើត Sub User';
                                    // required: sub fields
                                    toggleRequired(normalBox,false);
                                    // Mark sub required fields
                                    ['sub_id','sub_name','sub_password'].forEach(function(n){ var el=document.querySelector('input[name="'+n+'"]'); if(el) el.setAttribute('required','required'); });
                                } else {
                                    normalBox.style.display='block';
                                    subBox.style.display='none';
                                    actionInput.value='add_user';
                                    submitLabel.textContent='បង្កើត User';
                                    // required: normal fields
                                    ['new_id','new_name'].forEach(function(n){ var el=document.querySelector('input[name="'+n+'"]'); if(el) el.setAttribute('required','required'); });
                                    toggleRequired(subBox,false);
                                }
                            });
                        })();
                    </script>

                <?php elseif ($user_action === 'create_admin' && hasPageAccess($mysqli, 'users', 'create_admin', $admin_id_check)): ?>
                    <h2 id="create-admin-form"><i class="fa-solid fa-user-secret"></i> បង្កើតគណនី Admin ថ្មី (សម្រាប់ Admin Panel)</h2>
                    <?php if ($is_super_admin): ?>
                    <div class="admin-reg-box">
                        <form id="addAdminForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="add_admin">
                            <div class="form-group"><label><i class="fa-solid fa-id-badge"></i> Admin ID:</label><input type="text" name="admin_id" class="form-control" required></div>
                            <div class="form-group"><label><i class="fa-solid fa-user-tie"></i> Admin Name:</label><input type="text" name="admin_name" class="form-control" required></div>
                            <div class="form-group"><label><i class="fa-solid fa-lock"></i> Admin Password:</label><input type="password" name="admin_password" class="form-control" required></div>
                            <button type="submit" class="btn btn-danger"><i class="fa-solid fa-user-lock"></i> បង្កើត Admin</button>
                        </form>
                    </div>
                    <?php else: ?>
                    <div class="alert alert-danger"><i class="fa-solid fa-lock"></i> **ការបដិសេធសិទ្ធិ:** មានតែ **Super Admin** ប៉ុណ្ណោះដែលអាចបង្កើតគណនី Admin បានទេ។</div>
                    <?php endif; ?>

                <?php elseif ($user_action === 'list_users' && hasPageAccess($mysqli, 'users', 'list_users', $admin_id_check)): ?>
                    <h3 style="margin-top: 40px;" id="user-list"><i class="fa-solid fa-list-ul"></i> បញ្ជីអ្នកប្រើប្រាស់</h3>
                    <?php
                    $base_query = "SELECT employee_id, name, user_role, is_super_admin, access_mode, expiry_datetime, employment_status, leave_date, custom_data FROM users ";
                    $where_clause = "";
                    $selected_group_id = isset($_GET['group_id']) ? (int)$_GET['group_id'] : 0;

                    if (!$is_super_admin) {
                        $where_clause = " WHERE created_by_admin_id = '{$mysqli->real_escape_string($current_admin_id)}' OR employee_id = '{$mysqli->real_escape_string($current_admin_id)}' ";
                    }

                    $users_list = $mysqli->query($base_query . $where_clause . " ORDER BY employee_id ASC");

                    // ទាញយក Field Labels ទាំងអស់ម្តង ដើម្បីឱ្យដំណើរការលឿន
                    $admin_fields_map = [];
                    $fields_sql = "SELECT field_key, field_label FROM user_form_fields WHERE admin_id = ? ORDER BY id ASC";
                    if ($fields_stmt = $mysqli->prepare($fields_sql)) {
                        $fields_stmt->bind_param("s", $current_admin_id);
                        $fields_stmt->execute();
                        $fields_result = $fields_stmt->get_result();
                        while ($field_row = $fields_result->fetch_assoc()) {
                            $admin_fields_map[$field_row['field_key']] = $field_row['field_label'];
                        }
                        $fields_stmt->close();
                    }

                    if ($users_list && $users_list->num_rows > 0):
                    ?>
                    <div class="user-toolbar" role="toolbar" aria-label="User bulk/group actions">
                        <div class="segment-label" style="display:flex; gap:6px; align-items:center;">
                            <input type="text" id="searchUserID" class="form-control" placeholder="ស្វែងរក ID..." style="min-width: 100px; height: 32px; font-size: 13px;">
                            <input type="text" id="searchUserName" class="form-control" placeholder="ស្វែងរកឈ្មោះ..." style="min-width: 130px; height: 32px; font-size: 13px;">
                            <button type="button" id="searchUserBtn" class="btn btn-primary btn-sm" style="height: 32px; padding: 0 10px;">
                                <i class="fa-solid fa-magnifying-glass"></i>
                            </button>
                        </div>
                        <div class="segment-label" style="display:flex; gap:6px; align-items:center;">
                            <button type="button" id="bulkDeleteBtn" class="btn btn-danger btn-sm" disabled>
                                <i class="fa-solid fa-trash"></i> លុបដែលបានជ្រើស
                            </button>
                        </div>
                        <?php
                        // Group management mini UI
                        ensure_user_groups_table($mysqli);
                        $groups_sql = $mysqli->prepare("SELECT g.id, g.group_name, COUNT(u.employee_id) AS user_count
                                                          FROM user_skill_groups g
                                                          LEFT JOIN users u ON CAST(JSON_UNQUOTE(JSON_EXTRACT(u.custom_data,'$.group_id')) AS UNSIGNED) = g.id AND u.created_by_admin_id = g.admin_id
                                                          WHERE g.admin_id = ?
                                                          GROUP BY g.id, g.group_name
                                                          ORDER BY g.sort_order ASC, g.group_name ASC");
                        $groups_sql->bind_param("s", $current_admin_id);
                        $groups_sql->execute();
                        $groups_list = $groups_sql->get_result();
                        echo '<div class="form-group segment-label" style="margin:0; display:flex; align-items:center; gap:6px;">';
                        echo '<label style="margin:0;"><i class="fa-solid fa-layer-group"></i> ក្រុម:</label>';
                        echo '<select id="filter_user_group" class="form-control" onchange="applyGroupFilter(this.value)">';
                        echo '<option value="">គ្រប់ក្រុម</option>';
                        while($g = $groups_list->fetch_assoc()) {
                            $sel = ($selected_group_id === (int)$g['id']) ? 'selected' : '';
                            echo '<option value="'.(int)$g['id'].'" '.$sel.'>'.htmlspecialchars($g['group_name']).' ('.(int)$g['user_count'].')</option>';
                        }
                        echo '</select>';
                        echo '</div>';
                        $groups_sql->close();
                        ?>
                        <form id="createGroupInlineForm" class="ajax-form" style="display:flex; gap:6px; align-items:center;">
                            <input type="hidden" name="ajax_action" value="add_user_group">
                            <input type="text" name="group_name" class="form-control" placeholder="បង្កើតក្រុមថ្មី">
                            <button type="submit" class="btn btn-primary btn-sm" title="បង្កើតក្រុម"><i class="fa-solid fa-plus"></i></button>
                        </form>
                        <?php if (canManageUserGroups($mysqli, $admin_id_check)): ?>
                        <?php
                            // Load groups again for bulk assignment dropdown (separate from filter)
                            $assign_groups_stmt = $mysqli->prepare("SELECT id, group_name FROM user_skill_groups WHERE admin_id = ? ORDER BY sort_order ASC, group_name ASC");
                            $assign_groups_stmt->bind_param("s", $current_admin_id);
                            $assign_groups_stmt->execute();
                            $assign_groups_result = $assign_groups_stmt->get_result();
                        ?>
                        <form id="assignSelectedGroupForm" class="segment-label" style="display:flex; gap:6px; align-items:center;" onsubmit="return false;">
                            <label style="margin:0;"><i class="fa-solid fa-user-group"></i> កំណត់ក្រុម Selected:</label>
                            <select name="bulk_group_id" id="bulk_group_id" class="form-control">
                                <option value="">— ដកចេញពីក្រុម —</option>
                                <?php if ($assign_groups_result && $assign_groups_result->num_rows>0): while($ag = $assign_groups_result->fetch_assoc()): ?>
                                    <option value="<?php echo (int)$ag['id']; ?>"><?php echo htmlspecialchars($ag['group_name']); ?></option>
                                <?php endwhile; endif; ?>
                            </select>
                            <button type="submit" id="assignSelectedGroupBtn" class="btn btn-secondary btn-sm" disabled><i class="fa-solid fa-check"></i> កំណត់ក្រុម</button>
                        </form>
                        <?php $assign_groups_stmt && $assign_groups_stmt->close(); ?>
                        <?php endif; ?>
                    </div>
                    <table class="table" id="usersTable">
                        <thead>
                            <tr data-emp="<?php echo htmlspecialchars($user['employee_id']); ?>" data-group-id="<?php echo (int)$user_group_id; ?>">
                                <th style="width:32px; text-align:center;"><input type="checkbox" id="selectAllUsers"></th>
                                <th>ID</th><th>ឈ្មោះ</th><th>ព័ត៌មានខ្លះៗ</th>
                                <th>តួនាទីប្រព័ន្ធ</th><th>Subscription</th>
                                <th>ស្ថានភាពធ្វើការ</th><th>ថ្ងៃលែងធ្វើការ</th>
                                <th>គ្រប់គ្រងម៉ោង</th>
                                <?php if ($is_super_admin): ?><th>គ្រប់គ្រងសិទ្ធិ</th><?php endif; ?>
                                <th>សកម្មភាព</th>
                            </tr>
                        </thead>
                        <tbody id="usersTableBody">
                        <?php
                        // Collect users with their group meta, sort by group's sort_order then ID, render with one header per group
                        $users_sorted = [];
                        $group_meta = [];
                        // Preload all groups for current admin for order and name
                        if ($stmt_gm = $mysqli->prepare("SELECT id, group_name, sort_order FROM user_skill_groups WHERE admin_id = ?")) {
                            $stmt_gm->bind_param('s', $current_admin_id);
                            $stmt_gm->execute();
                            $res_gm = $stmt_gm->get_result();
                            if ($res_gm) {
                                while ($gm = $res_gm->fetch_assoc()) {
                                    $gidm = (int)$gm['id'];
                                    $group_meta[$gidm] = [ 'name' => ($gm['group_name'] ?? ''), 'order' => (int)($gm['sort_order'] ?? 100000) ];
                                }
                            }
                            $stmt_gm->close();
                        }
                        while ($user = $users_list->fetch_assoc()) {
                            $cd = json_decode($user['custom_data'] ?? '{}', true) ?: [];
                            $user_group_id = isset($cd['group_id']) ? (int)$cd['group_id'] : 0;
                            if ($selected_group_id > 0 && $user_group_id !== $selected_group_id) { continue; }
                            $g_name = ($user_group_id > 0 && isset($group_meta[$user_group_id])) ? $group_meta[$user_group_id]['name'] : 'គ្មានក្រុម';
                            $g_order = ($user_group_id > 0 && isset($group_meta[$user_group_id])) ? $group_meta[$user_group_id]['order'] : 999999;
                            $users_sorted[] = [ 'row' => $user, 'group_name' => $g_name, 'group_id' => $user_group_id, 'group_order' => $g_order ];
                        }
                        usort($users_sorted, function($a, $b){
                            if ($a['group_order'] === $b['group_order']) {
                                return strcmp((string)$a['row']['employee_id'], (string)$b['row']['employee_id']);
                            }
                            return $a['group_order'] <=> $b['group_order'];
                        });
                        $current_group_header = null;
                        foreach ($users_sorted as $item):
                            $user = $item['row'];
                            $cd = json_decode($user['custom_data'] ?? '{}', true) ?: [];
                            $user_group_id = $item['group_id'];
                            $user_group_name = ($item['group_name'] !== '') ? $item['group_name'] : 'គ្មានក្រុម';
                            $header_name = $user_group_name;
                            if ($header_name !== $current_group_header) {
                                $current_group_header = $header_name;
                                $gid_attr = $user_group_id > 0 ? (int)$user_group_id : 0;
                                echo '<tr class="group-header" data-group-id="'.$gid_attr.'" draggable="true" style="background:#f2f4f5;">';
                                echo '<td colspan="100" style="font-weight:600; color:#2c3e50">';
                                echo '<span class="drag-handle" title="អូសក្រុមនេះឡើង ឬចុះ" style="cursor:move; margin-right:8px;">&#9776;</span>';
                                echo '<i class="fa-solid fa-folder-open"></i> ' . htmlspecialchars($current_group_header);
                                echo '</td>';
                                echo '</tr>';
                            }
                        ?>
                            <tr class="user-row" id="user-row-<?php echo htmlspecialchars($user['employee_id']); ?>" data-group-id="<?php echo $user_group_id > 0 ? (int)$user_group_id : 0; ?>">
                                <td style="text-align:center;">
                                    <?php if ($user['user_role'] == 'User'): ?>
                                        <input type="checkbox" class="user-select" value="<?php echo htmlspecialchars($user['employee_id']); ?>">
                                    <?php else: ?>
                                        <span style="color:#bdc3c7;">—</span>
                                    <?php endif; ?>
                                </td>
                                <td><?php echo htmlspecialchars($user['employee_id']); ?></td>
                                <td class="user-name-cell"><?php echo htmlspecialchars($user['name']); ?></td>
                                <td class="user-info-brief">
                                    <?php
                                    $custom_data = json_decode($user['custom_data'] ?? '{}', true);
                                    $avatar_html = '';
                                    if (!empty($custom_data['avatar'])) {
                                        $raw_avatar = $custom_data['avatar'];
                                        $fs_path = __DIR__ . DIRECTORY_SEPARATOR . str_replace(['../','./'], '', $raw_avatar);
                                        $v = @file_exists($fs_path) ? @filemtime($fs_path) : time();
                                        $avatar_src = htmlspecialchars($raw_avatar . '?v=' . $v);
                                        $avatar_html = "<div style='float:left; margin-right:8px;'><img src='{$avatar_src}' alt='avatar' style='width:48px; height:48px; object-fit:cover; border-radius:6px; border:1px solid #e6e6e6;' loading='lazy' decoding='async'></div>";
                                    }
                                    $info_parts = [];
                                    if (!empty($admin_fields_map) && is_array($custom_data)) {
                                        foreach ($admin_fields_map as $key => $label) {
                                            if (isset($custom_data[$key]) && $custom_data[$key] !== '') {
                                                $info_parts[] = '<strong>' . htmlspecialchars($label) . ':</strong> ' . htmlspecialchars($custom_data[$key]);
                                            }
                                        }
                                    }
                                    if (empty($info_parts) && $avatar_html === '') {
                                        echo 'N/A';
                                    } else {
                                        // Show avatar (if any) + up to 2 custom fields
                                        echo $avatar_html;
                                        $display_parts = array_slice($info_parts, 0, 2);
                                        echo implode('<br>', $display_parts);
                                        if (count($info_parts) > 2) {
                                            echo '<br><small>...</small>';
                                        }
                                    }
                                    ?>
                                </td>
                                <td class="user-role-cell">
									<span class='status-<?php echo strtolower($user['user_role'] ?? 'user'); ?>' style="background: <?php echo (strtolower($user['user_role'] ?? 'user') == 'admin') ? ($user['is_super_admin'] ? '#c0392b' : 'var(--primary-color)') : '#2ecc71'; ?>; padding: 4px 8px; border-radius: 4px; color: white; font-weight: 600;">
										<?php
											if ($user['user_role'] == 'Admin') { echo $user['is_super_admin'] ? 'Super Admin' : 'Admin'; }
                                            else { echo htmlspecialchars($user['user_role'] ?? 'User'); }
										?>
									</span>
								</td>
                                <td class="user-sub-cell">
                                    <?php if ($user['user_role'] == 'Admin'): ?>
                                        <span style="font-weight: 600; color: <?php echo $user['access_mode'] == 'Expired' ? '#e74c3c' : ($user['access_mode'] == 'Paid' ? '#2980b9' : '#e67e22'); ?>">
                                            <?php echo htmlspecialchars($user['access_mode'] ?? 'Free'); ?>
                                            <?php echo ($user['access_mode'] == 'Paid' && $user['expiry_datetime']) ? '('.date('d/M/Y H:i', strtotime($user['expiry_datetime'])).')' : ''; ?>
                                        </span>
                                    <?php else: ?>
                                        <span style="color: #7f8c8d; font-style: italic;">N/A (User)</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($user['user_role']==='User'): ?>
                                        <?php
                                            $empStatus = $user['employment_status'] ?? 'Active';
                                            $badgeColor = ($empStatus==='Active'?'#2ecc71':($empStatus==='Suspended'?'#f39c12':'#e74c3c'));
                                        ?>
                                        <div style="display:flex; gap:6px; align-items:center;">
                                            <span class="badge" style="background: <?php echo $badgeColor; ?>; color:#fff; border-radius:12px; padding:4px 8px; font-weight:600; min-width:72px; text-align:center;"><?php echo htmlspecialchars($empStatus); ?></span>
                                            <select class="form-control form-control-sm" style="min-width:120px;" onchange="updateEmploymentStatus('<?php echo htmlspecialchars($user['employee_id']); ?>', this.value, this.closest('tr').querySelector('.leave-date-input')?.value)">
                                                <option value="Active" <?php echo $empStatus==='Active'?'selected':''; ?>>Active</option>
                                                <option value="Suspended" <?php echo $empStatus==='Suspended'?'selected':''; ?>>Suspended</option>
                                                <option value="Resigned" <?php echo $empStatus==='Resigned'?'selected':''; ?>>Resigned</option>
                                            </select>
                                        </div>
                                    <?php else: ?>
                                        <span style="color:#7f8c8d; font-style:italic;">N/A</span>
                                    <?php endif; ?>
                                </td>
                                <td>
                                    <?php if ($user['user_role']==='User'): ?>
                                        <?php $leaveDate = $user['leave_date'] ?? ''; ?>
                                        <input type="date" class="form-control leave-date-input" value="<?php echo htmlspecialchars($leaveDate); ?>" onchange="updateEmploymentStatus('<?php echo htmlspecialchars($user['employee_id']); ?>', this.closest('tr').querySelector('select').value, this.value)" />
                                    <?php else: ?>
                                        <span style="color:#7f8c8d; font-style:italic;">N/A</span>
                                    <?php endif; ?>
                                </td>

                                <td>
                                    <?php if ($user['user_role'] == 'User' && canManageTimeRules($mysqli, $admin_id_check)): ?>
                                        <a href="?page=users&action=edit_rules&id=<?php echo $user['employee_id']; ?>" class="btn btn-primary btn-sm"><i class="fa-solid fa-clock"></i> គ្រប់គ្រងច្បាប់ម៉ោង</a>
                                    <?php else: ?>
                                        <span style="color: #7f8c8d; font-style: italic;">N/A</span>
                                    <?php endif; ?>
                                </td>
                                <?php if ($is_super_admin): ?>
                                <td>
                                    <?php if ($user['user_role'] == 'Admin'): ?>
                                        <div class="access-button-group">
                                            <a href="?page=users&action=edit_admin_access&id=<?php echo $user['employee_id']; ?>" class="btn btn-warning btn-sm"><i class="fa-solid fa-sliders"></i> Page</a>
                                            <a href="?page=users&action=edit_admin_subscription&id=<?php echo $user['employee_id']; ?>" class="btn btn-danger btn-sm"><i class="fa-solid fa-calendar-check"></i> Sub</a>
                                        </div>
                                    <?php else: ?>
                                        <span style="color: #7f8c8d; font-style: italic;">N/A</span>
                                    <?php endif; ?>
                                </td>
                                <?php endif; ?>
                                <td>
                                    <div class="user-actions-dropdown" data-user-id="<?php echo htmlspecialchars($user['employee_id']); ?>">
                                        <button type="button" class="btn btn-outline-secondary btn-sm dropdown-toggle" aria-haspopup="true" aria-expanded="false" title="អំពើ">
                                            <i class="fa-solid fa-caret-down"></i>
                                        </button>
                                        <div class="dropdown-menu" role="menu">
                                            <button type="button" class="dropdown-item" onclick="editUserModal('<?php echo htmlspecialchars($user['employee_id']); ?>')">
                                                <i class="fa-solid fa-pen-to-square"></i> Edit Info
                                            </button>
                                            <?php if ($user['user_role'] == 'User' && hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check)): ?>
                                            <button type="button" class="dropdown-item open-duplicate-user" data-src-id="<?php echo htmlspecialchars($user['employee_id']); ?>" data-src-name="<?php echo htmlspecialchars($user['name'], ENT_QUOTES); ?>">
                                                <i class="fa-solid fa-clone"></i> Duplicate
                                            </button>
                                            <?php endif; ?>
                                            <?php if ($user['user_role'] == 'User' && (hasPageAccess($mysqli, 'users', 'create_user', $admin_id_check) || hasPageAccess($mysqli, 'users', 'list_users', $admin_id_check))): ?>
                                            <button type="button" class="dropdown-item text-danger ajax-delete-link" data-ajax-action="delete_user" data-user-id="<?php echo htmlspecialchars($user['employee_id']); ?>" data-confirm="តើអ្នកពិតជាចង់លុប User នេះមែនទេ?">
                                                <i class="fa-solid fa-trash"></i> លុប
                                            </button>
                                            <?php endif; ?>
                                        </div>
                                    </div>
                                </td>
                            </tr>
                        <?php endforeach; ?>
                        </tbody>
                    </table>
                    <?php $users_list->close(); else: ?>
                        <p>មិនមានទិន្នន័យអ្នកប្រើប្រាស់ទេ។</p>
                    <?php endif; ?>

                <?php else: ?>
                <?php endif; ?>

            <?php endif; ?>

            <?php if ($current_page == 'locations'):
                $location_action = $_GET['action'] ?? 'list_locations';
            ?>
                <h2><i class="fa-solid fa-location-dot"></i> គ្រប់គ្រងទីតាំង និង QR Code</h2>

                <?php if ($location_action === 'create_location' && hasPageAccess($mysqli, 'locations', 'create_location', $admin_id_check)): ?>
                    <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                        <h3 style="margin-top: 0;"><i class="fa-solid fa-square-plus"></i> បង្កើតទីតាំង Check-In/Out ថ្មី</h3>
                        <form id="addLocationForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="add_location">
                            <div class="form-group"><label><i class="fa-solid fa-map-pin"></i> ឈ្មោះទីតាំង (ឧ. Head Office):</label><input type="text" name="location_name" class="form-control" required></div>
                            <div style="display: flex; gap: 20px;">
                                <div class="form-group" style="flex: 1;"><label><i class="fa-solid fa-globe"></i> Latitude:</label><input type="text" name="latitude" class="form-control" placeholder="11.5564" required></div>
                                <div class="form-group" style="flex: 1;"><label><i class="fa-solid fa-globe"></i> Longitude:</label><input type="text" name="longitude" class="form-control" placeholder="104.9282" required></div>
                                <div class="form-group" style="flex: 0 0 150px;"><label><i class="fa-solid fa-bullseye"></i> រង្វង់ (ម៉ែត្រ):</label><input type="number" name="radius_meters" class="form-control" value="100" required></div>
                            </div>
                            <button type="submit" class="btn btn-success"><i class="fa-solid fa-circle-plus"></i> បង្កើតទីតាំង</button>
                        </form>
                    </div>
                <?php elseif ($location_action === 'assign_location' && hasPageAccess($mysqli, 'locations', 'assign_location', $admin_id_check)): ?>
                    <div style="background: #ecf0f1; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                        <h3 style="margin-top: 0;"><i class="fa-solid fa-user-check"></i> កំណត់ទីតាំងសម្រាប់បុគ្គលិក</h3>
                        <form id="assignLocationForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="assign_user_location">
                            <?php
                            $users_only_sql = "SELECT employee_id, name FROM users WHERE user_role = 'User' AND (created_by_admin_id = ? OR ? = TRUE) ORDER BY name ASC";
                            $user_stmt = $mysqli->prepare($users_only_sql);
                            $user_stmt->bind_param("si", $current_admin_id, $is_super_admin);
                            $user_stmt->execute();
                            $users_only_list = $user_stmt->get_result();
                            $locations_sql = "SELECT id, location_name FROM locations WHERE (created_by_admin_id = ? OR ? = TRUE) ORDER BY location_name ASC";
                            $loc_stmt = $mysqli->prepare($locations_sql);
                            $loc_stmt->bind_param("si", $current_admin_id, $is_super_admin);
                            $loc_stmt->execute();
                            $locations_selection = $loc_stmt->get_result();
                            ?>
                            <div style="display: flex; gap: 20px; align-items: flex-start;">
                                <div class="form-group" style="flex: 1;">
                                    <label><i class="fa-solid fa-users"></i> ជ្រើសរើសបុគ្គលិក (អាចច្រើន):</label>
                                    <details>
                                        <summary>ចុចដើម្បីជ្រើសរើសបុគ្គលិក</summary>
                                        <div class="checkbox-container">
                                            <?php if ($users_only_list && $users_only_list->num_rows > 0):
                                                $users_only_list->data_seek(0);
                                                while ($user = $users_only_list->fetch_assoc()): ?>
                                            <div class="checkbox-item">
                                                <input type="checkbox" name="employee_ids[]" value="<?php echo htmlspecialchars($user['employee_id']); ?>" id="user_<?php echo htmlspecialchars($user['employee_id']); ?>">
                                                <label for="user_<?php echo htmlspecialchars($user['employee_id']); ?>"><?php echo htmlspecialchars($user['name']) . " (" . htmlspecialchars($user['employee_id']) . ")"; ?></label>
                                            </div>
                                            <?php endwhile; $users_only_list->close(); else: ?>
                                                <p style="text-align: center; color: #7f8c8d;">មិនទាន់មាន User នៅឡើយទេ</p>
                                            <?php endif; ?>
                                        </div>
                                    </details>
                                </div>
                                <div class="form-group" style="flex: 1;">
                                    <label><i class="fa-solid fa-map-location-dot"></i> ជ្រើសរើសទីតាំង (អាចច្រើន):</label>
                                    <details>
                                        <summary>ចុចដើម្បីជ្រើសរើសទីតាំង</summary>
                                        <div class="checkbox-container">
                                            <?php if ($locations_selection && $locations_selection->num_rows > 0):
                                                $locations_selection->data_seek(0);
                                                while ($loc = $locations_selection->fetch_assoc()): ?>
                                            <div class="checkbox-item">
                                                <input type="checkbox" name="location_ids[]" value="<?php echo htmlspecialchars($loc['id']); ?>" id="loc_<?php echo htmlspecialchars($loc['id']); ?>">
                                                <label for="loc_<?php echo htmlspecialchars($loc['id']); ?>"><?php echo htmlspecialchars($loc['location_name']); ?></label>
                                            </div>
                                            <?php endwhile; $locations_selection->close(); else: ?>
                                                <p style="text-align: center; color: #7f8c8d;">មិនទាន់មានទីតាំងនៅឡើយទេ</p>
                                            <?php endif; ?>
                                        </div>
                                    </details>
                                </div>
                            </div>
                            <div class="form-group" style="max-width: 300px; margin-top: 10px;">
                                <label><i class="fa-solid fa-bullseye"></i> កំណត់រង្វង់ផ្ទាល់ខ្លួន (m)</label>
                                <input type="number" name="custom_radius_meters" class="form-control" value="100" min="10" required>
                            </div>
                            <button type="submit" class="btn btn-danger"><i class="fa-solid fa-location-arrow"></i> កំណត់/Update ទីតាំង</button>
                        </form>
                    </div>
                <?php elseif ($location_action === 'list_locations' && hasPageAccess($mysqli, 'locations', 'list_locations', $admin_id_check)): ?>
                    <h3><i class="fa-solid fa-list-ul"></i> បញ្ជីទីតាំង Check-In/Out (QR Codes)</h3>
                    <p class="alert alert-info"><i class="fa-solid fa-circle-info"></i> **QR Code:** ចុចលើរូបភាព QR ដើម្បី Pop up រូបភាពធំសម្រាប់ទាញយក។</p>
                    <?php
                    $locations_sql = "SELECT * FROM locations" . ($is_super_admin ? "" : " WHERE created_by_admin_id = ?") . " ORDER BY id DESC";
                    $loc_list_stmt = $mysqli->prepare($locations_sql);
                    if(!$is_super_admin) $loc_list_stmt->bind_param("s", $current_admin_id);
                    $loc_list_stmt->execute();
                    $locations_list = $loc_list_stmt->get_result();

                    if ($locations_list && $locations_list->num_rows > 0):
                    ?>
                    <table class="table">
                        <thead><tr><th>ID</th><th>ឈ្មោះទីតាំង</th><th>GPS (Lat, Lon)</th><th>រង្វង់ Default (m)</th><th>QR Code</th><th>សកម្មភាព</th></tr></thead>
                        <tbody>
                        <?php while ($loc = $locations_list->fetch_assoc()):
                               $qr_data_array = ['location_id' => $loc['id'], 'secret' => $loc['qr_secret']];
                               $qr_data_string = json_encode($qr_data_array);
                               $qr_url_small = 'https://quickchart.io/qr?size=80x80&text=' . urlencode($qr_data_string);
                               $qr_url_large = 'https://quickchart.io/qr?size=500x500&text=' . urlencode($qr_data_string);
                        ?>
                            <tr>
                                <td><?php echo htmlspecialchars($loc['id']); ?></td>
                                <td><?php echo htmlspecialchars($loc['location_name']); ?></td>
                                <td><?php echo htmlspecialchars($loc['latitude']) . ", " . htmlspecialchars($loc['longitude']); ?></td>
                                <td><?php echo htmlspecialchars($loc['radius_meters']); ?></td>
                                <td>
                                    <img src="<?php echo $qr_url_small; ?>" alt="QR Code" width="80" height="80" style="cursor: pointer;" loading="lazy" decoding="async" onclick="showQrModal('<?php echo htmlspecialchars($qr_url_large); ?>', 'QR_<?php echo htmlspecialchars(str_replace(' ', '_', $loc['location_name'])); ?>_ID<?php echo $loc['id']; ?>.png')" onerror="this.style.display='none'; this.nextElementSibling.style.display='inline';">
                                    <span style="display: none; color: #e74c3c; font-size: 0.8em;"><i class="fa-solid fa-xmark"></i> បញ្ហា</span>
                                    <div>
                                        <button
                                            type="button"
                                            class="btn btn-secondary btn-sm"
                                            style="margin-top:6px;"
                                            data-qr='<?php echo htmlspecialchars($qr_data_string, ENT_QUOTES); ?>'
                                            data-locname="<?php echo htmlspecialchars($loc['location_name'], ENT_QUOTES); ?>"
                                            onclick="openQrDesigner(this)"
                                        >
                                            <i class="fa-solid fa-wand-magic-sparkles"></i> Design
                                        </button>
                                    </div>
                                </td>
                                <td>
                                    <button type="button" class="btn btn-primary btn-sm" onclick="editLocationModal('<?php echo $loc['id']; ?>','<?php echo htmlspecialchars($loc['location_name']); ?>','<?php echo htmlspecialchars($loc['latitude']); ?>','<?php echo htmlspecialchars($loc['longitude']); ?>','<?php echo htmlspecialchars($loc['radius_meters']); ?>')"><i class="fa-solid fa-pen-to-square"></i> កែ</button>
                                    <a href="#" data-ajax-action="delete_location" data-loc-id="<?php echo $loc['id']; ?>" class="btn btn-danger btn-sm ajax-delete-link" data-confirm="តើអ្នកពិតជាចង់លុបទីតាំង <?php echo htmlspecialchars($loc['location_name']); ?> នេះមែនទេ? (វានឹងលុបការកំណត់របស់បុគ្គលិកផងដែរ)"><i class="fa-solid fa-trash-can"></i> លុប</a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                        </tbody>
                    </table>
                    <?php $locations_list->close(); else: ?>
                           <p style="font-style: italic;">មិនទាន់មានទីតាំង Check-In ណាមួយត្រូវបានបង្កើតនៅឡើយទេ។</p>
                    <?php endif; ?>

                    <hr style="border-top: 2px dashed #bdc3c7;">

                    <h3><i class="fa-solid fa-people-arrows"></i> បញ្ជីកំណត់ទីតាំងសម្រាប់បុគ្គលិក</h3>
                    <?php
                    $assigned_sql = "
                            SELECT ul.id as assign_id, ul.custom_radius_meters, u.employee_id, u.name as user_name, l.location_name
                            FROM user_locations ul
                            JOIN users u ON ul.employee_id = u.employee_id
                            JOIN locations l ON ul.location_id = l.id
                            " . ($is_super_admin ? "" : " WHERE ul.created_by_admin_id = ?") . "
                            ORDER BY u.name ASC, l.location_name ASC";
                    $assigned_stmt = $mysqli->prepare($assigned_sql);
                    if(!$is_super_admin) $assigned_stmt->bind_param("s", $current_admin_id);
                    $assigned_stmt->execute();
                    $assigned_list = $assigned_stmt->get_result();

                    if ($assigned_list && $assigned_list->num_rows > 0):
                    ?>
                    <table class="table">
                        <thead><tr><th>ID កំណត់</th><th>អត្តលេខបុគ្គលិក</th><th>ឈ្មោះបុគ្គលិក</th><th>ទីតាំងដែលបានកំណត់</th><th>រង្វង់ផ្ទាល់ខ្លួន (m)</th><th>សកម្មភាព</th></tr></thead>
                        <tbody>
                        <?php while ($assign = $assigned_list->fetch_assoc()): ?>
                            <tr>
                                <td><?php echo htmlspecialchars($assign['assign_id']); ?></td>
                                <td><?php echo htmlspecialchars($assign['employee_id']); ?></td>
                                <td><?php echo htmlspecialchars($assign['user_name']); ?></td>
                                <td><?php echo htmlspecialchars($assign['location_name']); ?></td>
                                <td><?php echo htmlspecialchars($assign['custom_radius_meters']); ?></td>
                                <td>
                                    <a href="#" data-ajax-action="unassign_location" data-assign-id="<?php echo $assign['assign_id']; ?>" class="btn btn-danger btn-sm ajax-delete-link" data-confirm="តើអ្នកពិតជាចង់លុបការកំណត់នេះចេញពីបុគ្គលិក <?php echo htmlspecialchars($assign['user_name']); ?> មែនទេ?"><i class="fa-solid fa-unlink"></i> លុបការកំណត់</a>
                                </td>
                            </tr>
                        <?php endwhile; ?>
                        </tbody>
                    </table>
                    <?php $assigned_list->close(); else: ?>
                           <p style="font-style: italic;">មិនទាន់មានបុគ្គលិកណាម្នាក់ត្រូវបានកំណត់ទីតាំងផ្ទាល់ខ្លួននៅឡើយទេ។</p>
                    <?php endif; ?>

                <?php else: ?>
                    <div class="alert alert-danger"><i class="fa-solid fa-lock"></i> **ការបដិសេធសិទ្ធិ:** អ្នកមិនមានសិទ្ធិចូលប្រើមុខងារនេះទេ។</div>
                <?php endif; ?>

            <?php endif; ?>

           <?php if ($current_page == 'tokens'):
    $token_action = $_GET['action'] ?? 'global_settings';
?>
    <h2><i class="fa-solid fa-lock-open"></i> គ្រប់គ្រង Token និង Session</h2>

    <?php if ($token_action === 'global_settings' && hasPageAccess($mysqli, 'tokens', 'global_settings', $admin_id_check)): ?>

        <div class="tokens-page-section" style="background: white; padding: 25px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05);">
            <h3 style="margin-top: 0; margin-bottom: 20px;"><i class="fa-solid fa-key"></i> កំណត់ចំនួន Token អតិបរមា</h3>
            <?php
            $max_tokens_stmt = $mysqli->prepare("SELECT global_max_tokens FROM users WHERE employee_id = ? LIMIT 1");
            $max_tokens_stmt->bind_param("s", $current_admin_id);
            $max_tokens_stmt->execute();
            $max_tokens_result = $max_tokens_stmt->get_result();
            $global_max_tokens = 1;
            if ($max_tokens_result && $max_tokens_result->num_rows > 0) {
                $max_tokens_row = $max_tokens_result->fetch_assoc();
                $global_max_tokens = $max_tokens_row['global_max_tokens'] ?? 1;
            }
            $max_tokens_stmt->close();
            ?>
            <form id="globalTokenSettingsForm" class="ajax-form">
                <input type="hidden" name="ajax_action" value="set_global_max_tokens">
                <div class="form-group">
                    <label for="global_max_tokens"><i class="fa-solid fa-hashtag"></i> ចំនួន Token អតិបរមាសម្រាប់ User នីមួយៗ:</label>
                    <input type="number" id="global_max_tokens" name="global_max_tokens" class="form-control" value="<?php echo $global_max_tokens; ?>" min="1" max="10" required>
                    <small class="form-text text-muted">ចំនួន Token អតិបរមាដែល User នីមួយៗអាចមានក្នុងពេលដំណាលគ្នា (1-10)។</small>
                </div>
                <button type="submit" class="btn btn-primary"><i class="fa-solid fa-save"></i> រក្សាទុកការកំណត់</button>
            </form>
        </div>

        <div class="tokens-page-section info-box">
            <h3 style="margin-top: 0; margin-bottom: 15px;"><i class="fa-solid fa-info-circle"></i> ព័ត៌មានបន្ថែម</h3>
            <ul>
                <li><strong>Token បច្ចុប្បន្ន:</strong> ប្រព័ន្ធប្រើ Token សម្រាប់គ្រប់គ្រង Session នៃ User នីមួយៗ</li>
                <li><strong>ការកំណត់នេះ:</strong> កំណត់ចំនួន Token អតិបរមាដែល User នីមួយៗអាចមានក្នុងពេលដំណាលគ្នា</li>
                <li><strong>ផលប៉ះពាល់:</strong> ការកំណត់នេះនឹងអនុវត្តលើ User ទាំងអស់ដែលស្ថិតក្រោមការគ្រប់គ្រងរបស់អ្នក (Per-Admin)</li>
            </ul>
        </div>

    <?php elseif ($token_action === 'active_sessions' && hasPageAccess($mysqli, 'tokens', 'active_sessions', $admin_id_check)): ?>
        <?php
        // Restrict visible sessions to this admin's users unless Super Admin
        $active_sessions_sql = "
            SELECT at.*, u.name as user_name, u.employee_id, u.user_role
            FROM active_tokens at
            JOIN users u ON at.employee_id = u.employee_id";
        if (!$is_super_admin) {
            $adminEsc = $mysqli->real_escape_string($current_admin_id);
            $active_sessions_sql .= " WHERE (u.created_by_admin_id = '" . $adminEsc . "' OR u.employee_id = '" . $adminEsc . "')";
        }
        $active_sessions_sql .= " ORDER BY at.created_at DESC";
        $active_sessions_query = $mysqli->query($active_sessions_sql);
        $session_count = $active_sessions_query ? $active_sessions_query->num_rows : 0;
        ?>
        <div class="tokens-page-section" style="background: white; padding: 25px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05);">
            <h3 style="margin-top: 0; margin-bottom: 20px;"><i class="fa-solid fa-list"></i> បញ្ជី Session សកម្ម</h3>

            <?php if ($session_count > 0): ?>
                <div class="session-count-info">
                    <i class="fa-solid fa-info-circle"></i> មាន <strong><?php echo $session_count; ?></strong> Session សកម្មសរុប។
                </div>
                <table class="table">
                    <thead>
                        <tr><th>ព័ត៌មានអ្នកប្រើប្រាស់</th><th>Token (សង្ខេប)</th><th>បង្កើតនៅ</th><th>សកម្មភាព</th></tr>
                    </thead>
                    <tbody>
                        <?php while ($session = $active_sessions_query->fetch_assoc()): ?>
                            <tr>
                                <td class="user-info-cell">
                                    <strong><?php echo htmlspecialchars($session['user_name']); ?></strong><br>
                                    <small><?php echo htmlspecialchars($session['employee_id']); ?></small>
                                </td>
                                <td><span class="token-id-display"><?php echo substr(htmlspecialchars($session['auth_token']), 0, 15) . '...'; ?></span></td>
                                <td><?php echo date('d-M-Y H:i:s', strtotime($session['created_at'])); ?></td>
                                <td><a href="#" data-ajax-action="revoke_token" data-token="<?php echo $session['auth_token']; ?>" class="btn btn-danger btn-sm ajax-delete-link" data-confirm="តើអ្នកពិតជាចង់លុប Token នេះមែនទេ? User នោះនឹងត្រូវបាន Log Out ដោយស្វ័យប្រវត្តិ។"><i class="fa-solid fa-delete-left"></i> Revoke Token</a></td>
                            </tr>
                        <?php endwhile; $active_sessions_query->close(); ?>
                    </tbody>
                </table>
            <?php else: ?>
                <div class="alert alert-info" style="margin: 20px 0;"><i class="fa-solid fa-info-circle"></i> មិនមាន Session សកម្មនៅក្នុងប្រព័ន្ធទេ។</div>
            <?php endif; ?>
        </div>
    <?php else: ?>
        <div class="alert alert-danger"><i class="fa-solid fa-lock"></i> <strong>ការបដិសេធសិទ្ធិ:</strong> អ្នកមិនមានសិទ្ធិចូលប្រើមុខងារនេះទេ។</div>
    <?php endif; ?>

            <?php elseif ($current_page == 'categories' && hasPageAccess($mysqli, 'categories', 'categories', $admin_id_check)): ?>
                <h2><i class="fa-solid fa-layer-group"></i> គ្រប់គ្រងក្រុមអ្នកប្រើប្រាស់ (Skill Groups)</h2>
                <p>បង្កើតក្រុមជំនាញ/ផ្នែក មុនសិន បន្ទាប់មកកំណត់ឈ្មោះបុគ្គលិកចូលក្រុមនីមួយៗ ដើម្បីងាយស្រួលមើល។</p>
                <?php ensure_user_groups_table($mysqli); ?>
                <div style="background: #ecf0f1; padding: 16px; border-radius: 8px; margin-bottom: 16px; display:flex; gap:10px; align-items:flex-end; flex-wrap:wrap;">
                    <form id="addGroupForm" class="ajax-form" style="display:flex; gap:8px; align-items:flex-end;">
                        <input type="hidden" name="ajax_action" value="add_user_group">
                        <div class="form-group" style="margin:0;">
                            <label>ឈ្មោះក្រុមថ្មី:</label>
                            <input type="text" name="group_name" class="form-control" placeholder="ឧ. ផ្នែកគណនេយ្យ" required>
                        </div>
                        <button type="submit" class="btn btn-primary"><i class="fa-solid fa-plus"></i> បង្កើតក្រុម</button>
                    </form>
                </div>
                <?php
                    // Load groups and count assigned users
                    $gstmt = $mysqli->prepare("SELECT id, group_name, sort_order FROM user_skill_groups WHERE admin_id = ? ORDER BY sort_order ASC, group_name ASC");
                    $gstmt->bind_param("s", $current_admin_id); $gstmt->execute(); $grs = $gstmt->get_result();
                ?>
                <table class="table" id="groupsTable">
                    <thead><tr><th style="width:44px;">&nbsp;</th><th>លេខរៀង</th><th>ឈ្មោះក្រុម</th><th>ចំនួនអ្នកប្រើប្រាស់</th><th>សកម្មភាព</th></tr></thead>
                    <tbody id="groupsTableBody">
                        <?php if ($grs && $grs->num_rows>0): while($gr = $grs->fetch_assoc()):
                            // Count users assigned
                            $cnt = 0;
                            if ($c = $mysqli->prepare("SELECT COUNT(*) AS c FROM users WHERE created_by_admin_id = ? AND JSON_EXTRACT(custom_data,'$.group_id') = ?")) {
                                $gid = (int)$gr['id'];
                                $c->bind_param("si", $current_admin_id, $gid); $c->execute(); $r=$c->get_result()->fetch_assoc(); $cnt = (int)($r['c'] ?? 0); $c->close();
                            }
                        ?>
                        <tr class="draggable-group" data-group-id="<?php echo (int)$gr['id']; ?>" draggable="true">
                            <td style="width:44px; cursor:move;" class="drag-cell" title="អូសដើម្បីរៀបលំដាប់">&#9776;</td>
                            <td style="width:110px;">
                                <input type="number" class="form-control group-sort-input" data-group-id="<?php echo (int)$gr['id']; ?>" value="<?php echo (int)$gr['sort_order']; ?>" title="លេខរៀង">
                            </td>
                            <td>
                                <form class="ajax-form" style="display:flex; gap:6px; align-items:center;">
                                    <input type="hidden" name="ajax_action" value="rename_user_group">
                                    <input type="hidden" name="group_id" value="<?php echo (int)$gr['id']; ?>">
                                    <input type="text" name="group_name" class="form-control" value="<?php echo htmlspecialchars($gr['group_name']); ?>">
                                    <button type="submit" class="btn btn-secondary btn-sm"><i class="fa-solid fa-pen"></i> កែ</button>
                                </form>
                            </td>
                            <td style="width:140px;"><span class="badge" style="background:#3498db; color:#fff; padding:4px 8px; border-radius:12px; font-weight:600;"><?php echo $cnt; ?></span></td>
                            <td style="width:140px;">
                                <a href="#" data-ajax-action="delete_user_group" data-group-id="<?php echo (int)$gr['id']; ?>" class="btn btn-danger btn-sm ajax-delete-link" data-confirm="លុបក្រុមនេះ? អ្នកប្រើប្រាស់ក្នុងក្រុមនឹងត្រូវដកចេញពីក្រុម។"><i class="fa-solid fa-trash"></i> លុប</a>
                            </td>
                        </tr>
                        <?php endwhile; else: ?>
                            <tr><td colspan="5" style="text-align:center; color:#7f8c8d;">មិនទាន់មានក្រុម</td></tr>
                        <?php endif; $gstmt->close(); ?>
                    </tbody>
                </table>
                <div style="margin-top:8px; display:flex; gap:8px;">
                    <button id="saveGroupOrderBtn" class="btn btn-outline-primary btn-sm"><i class="fa-solid fa-floppy-disk"></i> រក្សាទុកលំដាប់</button>
                    <span style="color:#7f8c8d; font-size:12px;">សូមអូសជួរដេកដើម្បីរៀបលំដាប់ ក្រោយមកចុច រក្សាទុកលំដាប់</span>
                </div>

                <h3 style="margin-top:20px;"><i class="fa-solid fa-user-group"></i> កំណត់អ្នកប្រើប្រាស់ទៅក្រុម</h3>
                <?php
                    // Users under this admin
                    $u_stmt = $mysqli->prepare("SELECT employee_id, name, custom_data FROM users WHERE user_role='User' AND (created_by_admin_id = ? OR ? = TRUE) ORDER BY name ASC");
                    $u_stmt->bind_param("si", $current_admin_id, $is_super_admin); $u_stmt->execute(); $ulist = $u_stmt->get_result();
                    $g_stmt2 = $mysqli->prepare("SELECT id, group_name FROM user_skill_groups WHERE admin_id = ? ORDER BY sort_order ASC, group_name ASC");
                    $g_stmt2->bind_param("s", $current_admin_id); $g_stmt2->execute(); $gsel = $g_stmt2->get_result();
                ?>
                <form id="assignGroupForm" class="ajax-form" style="background:#ecf0f1; padding:16px; border-radius:8px;">
                    <input type="hidden" name="ajax_action" value="assign_user_group">
                    <div style="display:flex; gap:16px; align-items:flex-start; flex-wrap:wrap;">
                        <div class="form-group" style="flex:1; min-width:260px;">
                            <label><i class="fa-solid fa-users"></i> ជ្រើសរើសបុគ្គលិក</label>
                            <details><summary>ចុចដើម្បីជ្រើស</summary>
                                <div class="checkbox-container">
                                    <?php if ($ulist && $ulist->num_rows>0): while($u = $ulist->fetch_assoc()): ?>
                                        <div class="checkbox-item"><input type="checkbox" name="employee_ids[]" value="<?php echo htmlspecialchars($u['employee_id']); ?>"> <label><?php echo htmlspecialchars($u['name']).' ('.htmlspecialchars($u['employee_id']).')'; ?></label></div>
                                    <?php endwhile; else: ?><p style="color:#7f8c8d;">គ្មាន User</p><?php endif; ?>
                                </div>
                            </details>
                        </div>
                        <div class="form-group" style="flex:1; min-width:220px;">
                            <label><i class="fa-solid fa-layer-group"></i> ជ្រើសក្រុម</label>
                            <select name="group_id" class="form-control">
                                <option value="">— ដកចេញពីក្រុម —</option>
                                <?php if ($gsel && $gsel->num_rows>0){ while($gg = $gsel->fetch_assoc()){ echo '<option value="'.(int)$gg['id'].'">'.htmlspecialchars($gg['group_name']).'</option>'; } } ?>
                            </select>
                        </div>
                    </div>
                    <button type="submit" class="btn btn-danger" style="margin-top:10px;"><i class="fa-solid fa-check"></i> កំណត់ក្រុម</button>
                </form>
            <?php endif; ?>

            <?php if ($current_page == 'settings'):
                $settings_action = $_GET['action'] ?? 'panel_settings';
            ?>
                <h2><i class="fa-solid fa-cogs"></i> ការកំណត់ប្រព័ន្ធ</h2>

                <?php if ($settings_action === 'panel_settings' && hasPageAccess($mysqli, 'settings', 'panel_settings', $admin_id_check)): ?>
                    <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                        <h3 style="margin-top: 0;"><i class="fa-solid fa-palette"></i> ការកំណត់ Panel ទូទៅ</h3>
                        <form id="panelSettingsForm" class="ajax-form" enctype="multipart/form-data">
                            <input type="hidden" name="ajax_action" value="save_panel_settings">

                            <div class="form-group">
                                <label for="panel_title"><i class="fa-solid fa-pen-to-square"></i> ឈ្មោះ Admin Panel:</label>
                                <input type="text" id="panel_title" name="panel_title" class="form-control" value="<?php echo htmlspecialchars($panel_title); ?>">
                            </div>
                            <div class="form-group">
                                <label for="panel_logo"><i class="fa-solid fa-image"></i> ប្តូរ Logo (ទុកឱ្យទំនេរ បើមិនចង់ប្តូរ):</label>
                                <input type="file" id="panel_logo" name="panel_logo" class="form-control" accept="image/png, image/jpeg, image/gif, image/svg+xml">
                                <?php if (!empty($panel_logo_path) && file_exists($panel_logo_path)): ?>
                                    <div style="margin-top: 10px;">Logo បច្ចុប្បន្ន: <img src="<?php echo htmlspecialchars($panel_logo_path); ?>" alt="Current Logo" style="max-height: 50px; background: #f0f0f0; padding: 5px; border-radius: 4px;"></div>
                                <?php endif; ?>
                            </div>
                            <div class="form-group checkbox-item">
                                <input type="checkbox" name="show_title_with_logo" id="show_title_with_logo" value="1" <?php echo $show_title_with_logo ? 'checked' : ''; ?>>
                                <label for="show_title_with_logo">បង្ហាញឈ្មោះជាមួយ Logo (បើមិន check គឺបង្ហាញតែ Logo)</label>
                            </div>
                            <hr>
                            <div class="form-group">
                                <label for="footer_text"><i class="fa-solid fa-copyright"></i> Footer Text (Copyright Info):</label>
                                <textarea id="footer_text" name="footer_text" class="form-control" rows="3"><?php echo htmlspecialchars($footer_text); ?></textarea>
                                <small class="form-text">អ្នកអាចប្រើ HTML tags មូលដ្ឋានបានដូចជា &lt;b&gt;, &lt;a href="..."&gt;, &lt;i&gt; ។</small>
                            </div>
                            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-save"></i> រក្សាទុកការកំណត់ Panel</button>
                        </form>

                        <form id="compressImagesForm" style="margin-top: 30px; border-top: 1px dashed #ccc; padding-top: 20px;">
                            <h4 style="margin-top: 0; color: #e67e22;"><i class="fa-solid fa-compress"></i> Optimize Storage (Compress Images)</h4>
                            <p class="text-muted" style="font-size: 13px;">
                                មុខងារនេះនឹងស្កេនរូបភាពទាំងអស់នៅក្នុង Folder <code>uploads/</code> និង <code>uploads/avatars/</code>។ ប្រសិនបើរូបភាពណាមានទំហំធំ (>300KB) ឬវិមាត្រធំពេក វានឹងត្រូវបាន Compress និង Resize (Max 1200px) ដោយស្វ័យប្រវត្តិដើម្បីសន្សំទំហំផ្ទុក។
                            </p>
                            <input type="hidden" name="ajax_action" value="batch_compress_existing_images">
                            <button type="submit" class="btn btn-warning" id="btnRunCompression"><i class="fa-solid fa-file-image"></i> Compress All Existing Images</button>
                        </form>
                        <script>
                        (function(){
                            const form = document.getElementById('compressImagesForm');
                            if(!form) return;
                            form.addEventListener('submit', function(e){
                                e.preventDefault();
                                if(!confirm('តើអ្នកពិតជាចង់ Compress រូបភាពទាំងអស់មែនទេ? សកម្មភាពនេះមិនអាចត្រឡប់ក្រោយបានទេ។')) return;
                                if(typeof submitAjaxForm === 'function') {
                                    submitAjaxForm(this);
                                }
                            });
                        })();
                        </script>
                    </div>
                <?php elseif ($settings_action === 'menu_settings' && hasPageAccess($mysqli, 'settings', 'menu_settings', $admin_id_check)):
                    $menu_settings_stmt = $mysqli->prepare("SELECT menu_key, menu_text, menu_order FROM sidebar_settings WHERE admin_id = ? ORDER BY menu_order ASC");
                    $menu_settings_stmt->bind_param("s", $current_admin_id);
                    $menu_settings_stmt->execute();
                    $menu_settings_query = $menu_settings_stmt->get_result();
                    $all_submenu_settings = [];
                    $submenu_settings_stmt = $mysqli->prepare("SELECT menu_key, action_key, submenu_text FROM submenu_settings WHERE admin_id = ?");
                    $submenu_settings_stmt->bind_param("s", $current_admin_id);
                    $submenu_settings_stmt->execute();
                    $submenu_settings_result = $submenu_settings_stmt->get_result();
                     if ($submenu_settings_result) {
                        while ($row = $submenu_settings_result->fetch_assoc()) {
                            $all_submenu_settings[$row['menu_key']][$row['action_key']] = $row['submenu_text'];
                        }
                    }
                    $submenu_settings_stmt->close();
                ?>
                    <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                        <h3 style="margin-top: 0;"><i class="fa-solid fa-list-ol"></i> កំណត់ Sidebar Menu</h3>
                        <p>អ្នកអាចប្តូរឈ្មោះ និងលេខរៀងរបស់ Menu នីមួយៗបាន។ លេខតូចនឹងនៅខាងលើ។</p>
                        <form id="menuSettingsForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="save_menu_settings">
                            <table class="table">
                                <thead>
                                    <tr><th>Menu Key (សម្រាប់ប្រព័ន្ធ)</th><th>ឈ្មោះបង្ហាញ (អាចកែបាន)</th><th style="width: 150px;">លេខរៀង (អាចកែបាន)</th></tr>
                                </thead>
                                <tbody>
                                    <?php if ($menu_settings_query) { while ($menu_item = $menu_settings_query->fetch_assoc()): ?>
                                    <tr>
                                        <td><strong><?php echo htmlspecialchars($menu_item['menu_key']); ?></strong></td>
                                        <td><input type="text" name="menu_text[<?php echo htmlspecialchars($menu_item['menu_key']); ?>]" class="form-control" value="<?php echo htmlspecialchars($menu_item['menu_text']); ?>"></td>
                                        <td><input type="number" name="menu_order[<?php echo htmlspecialchars($menu_item['menu_key']); ?>]" class="form-control" value="<?php echo htmlspecialchars($menu_item['menu_order']); ?>"></td>
                                    </tr>
                                    <?php if (isset($all_submenu_settings[$menu_item['menu_key']])): ?>
                                        <?php foreach ($all_submenu_settings[$menu_item['menu_key']] as $action_key => $submenu_text): ?>
                                            <tr class="submenu-setting-row">
                                                <td><?php echo htmlspecialchars($action_key); ?></td>
                                                <td colspan="2"><input type="text" name="submenu_text[<?php echo htmlspecialchars($menu_item['menu_key']); ?>][<?php echo htmlspecialchars($action_key); ?>]" class="form-control" value="<?php echo htmlspecialchars($submenu_text); ?>"></td>
                                            </tr>
                                        <?php endforeach; ?>
                                    <?php endif; ?>
                                    <?php endwhile; $menu_settings_query->close(); } ?>
                                </tbody>
                            </table>
                            <button type="submit" class="btn btn-primary" style="margin-top: 20px;"><i class="fa-solid fa-save"></i> រក្សាទុកការកំណត់ Menu</button>
                        </form>
                        <hr>
                        <h4 style="margin-top:30px;"><i class="fa-solid fa-eye-slash"></i> បិទ/បើក ការបង្ហាញ Sidebar Items</h4>
                        <p style="font-size:13px;">ជ្រើសរើស Items ដែលអ្នកចង់ <strong>លាក់</strong> ពី Sidebar (Admin/Sub User) សម្រាប់ Admin នេះ។ Sub User ក៏អនុវត្តតាម លុះត្រាតែសិទ្ធិខ្លួនចាក់ឆ្ពោះទៅម៉ឺនុយមិនបង្ហាញ។</p>
                        <?php
                        // Load existing hidden items from a system setting (JSON array)
                        $visibility_owner_id = resolveVisibilityOwnerId($mysqli, $current_admin_id);
                        $hidden_items_json = get_setting($mysqli, $visibility_owner_id, 'sidebar_hidden_items', '[]');
                        $hidden_items = json_decode($hidden_items_json, true);
                        if (!is_array($hidden_items)) { $hidden_items = []; }
                        ?>
                        <form id="sidebarVisibilityForm" class="ajax-form" style="margin-top:15px;">
                            <input type="hidden" name="ajax_action" value="save_sidebar_visibility">
                            <div style="display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:10px;">
                                <?php foreach ($admin_pages_list as $pageKey => $actionsArr): ?>
                                    <div style="border:1px solid #eee; padding:10px; border-radius:6px; background:#fdfdfd;">
                                        <strong style="font-size:13px; display:block; margin-bottom:6px;">
                                            <i class="fa-solid fa-folder-tree"></i> <?php echo htmlspecialchars($pageKey); ?>
                                        </strong>
                                        <label style="display:flex; align-items:center; gap:6px; font-size:12px; margin-bottom:4px;">
                                            <input type="checkbox" name="hide_page[]" value="<?php echo htmlspecialchars($pageKey); ?>" <?php echo in_array($pageKey,$hidden_items,true)?'checked':''; ?>> លាក់ Page
                                        </label>
                                        <?php foreach ($actionsArr as $actionKey => $actionLabel): ?>
                                            <?php if ($actionKey === $pageKey) continue; // skip redundant dashboard self action ?>
                                            <label style="display:flex; align-items:center; gap:6px; font-size:12px;">
                                                <input type="checkbox" name="hide_action[]" value="<?php echo htmlspecialchars($pageKey.'::'.$actionKey); ?>" <?php echo in_array($pageKey.'::'.$actionKey,$hidden_items,true)?'checked':''; ?>>
                                                លាក់: <?php echo htmlspecialchars($actionKey); ?>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endforeach; ?>
                            </div>
                            <button type="submit" class="btn btn-secondary" style="margin-top:15px;"><i class="fa-solid fa-eye"></i> រក្សាទុកការបិទ/បើក</button>
                        </form>
                        <script>
                        (function(){
                            document.getElementById('sidebarVisibilityForm').addEventListener('submit', function(e){
                                e.preventDefault();
                                var fd = new FormData(this);
                                fetch('admin_attendance.php',{method:'POST',body:fd,credentials:'same-origin'}).then(r=>r.json()).then(function(j){
                                    alert(j.message||'Saved');
                                    if(j.status==='success'){ location.reload(); }
                                }).catch(err=>alert('Network error '+err));
                            });
                        })();
                        </script>
                    </div>

                <?php elseif ($settings_action === 'manage_user_fields' && hasPageAccess($mysqli, 'settings', 'manage_user_fields', $admin_id_check)): ?>
                    <h2><i class="fa-solid fa-tasks"></i> គ្រប់គ្រង Fields សម្រាប់ទម្រង់បង្កើតអ្នកប្រើប្រាស់</h2>
                    <p>នៅទីនេះអ្នកអាចបន្ថែម, កែសម្រួល, ឬលុប Fields ដែលនឹងបង្ហាញនៅក្នុងទម្រង់ "បង្កើតអ្នកប្រើប្រាស់ថ្មី"។</p>

                    <div style="background: #ecf0f1; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
                        <h3 style="margin-top:0"><i class="fa-solid fa-plus-circle"></i> បន្ថែម Field ថ្មី</h3>
                        <form id="addUserFieldForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="add_user_field">
                            <div style="display: flex; gap: 15px; align-items: flex-end;">
                                <div class="form-group" style="flex: 3;">
                                    <label>ឈ្មោះ Field (Label):</label>
                                    <input type="text" name="field_label" class="form-control" placeholder="ឧ. លេខទូរស័ព្ទ" required>
                                </div>
                                <div class="form-group" style="flex: 2;">
                                    <label>ប្រភេទ Input:</label>
                                    <select name="field_type" class="form-control">
                                        <option value="text">Text</option>
                                        <option value="number">Number</option>
                                        <option value="email">Email</option>
                                        <option value="date">Date</option>
                                    </select>
                                </div>
                                <div class="form-group checkbox-item" style="margin-bottom: 10px; flex-shrink: 0;">
                                    <input type="checkbox" name="is_required" id="is_required" value="1">
                                    <label for="is_required">ត្រូវតែបំពេញ (Required)</label>
                                </div>
                                <div class="form-group" style="flex-shrink: 0;">
                                    <button type="submit" class="btn btn-success">បន្ថែម Field</button>
                                </div>
                            </div>
                        </form>
                    </div>

                    <h3><i class="fa-solid fa-list-ul"></i> Fields ដែលមានបច្ចុប្បន្ន</h3>
    <table class="table" id="userFieldsTable">
                                <thead>
                            <tr><th style="width:40px"></th><th>ឈ្មោះ Field (Label)</th><th>ប្រភេទ Input</th><th>Required?</th><th>Active?</th><th colspan="2">សកម្មភាព</th></tr>
                        </thead>
                        <tbody id="userFieldsList">
                            <?php
                            $fields_stmt = $mysqli->prepare("SELECT * FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC, id ASC");
                            $fields_stmt->bind_param("s", $current_admin_id);
                            $fields_stmt->execute();
                            $existing_fields = $fields_stmt->get_result();
                            if ($existing_fields && $existing_fields->num_rows > 0) {
                                while($field = $existing_fields->fetch_assoc()): ?>
                                <tr data-field-id="<?php echo $field['id']; ?>" draggable="true" class="draggable-field-row">
                                    <td style="cursor:grab; text-align:center; vertical-align:middle;"><i class="fa-solid fa-grip-vertical"></i></td>
                                    <td>
                                        <span class="field-label-display"><?php echo htmlspecialchars($field['field_label']); ?></span>
                                        <input type="text" class="field-label-input" value="<?php echo htmlspecialchars($field['field_label']); ?>" style="display:none; width:100%;" />
                                    </td>
                                    <td><?php echo htmlspecialchars($field['field_type']); ?></td>
                                    <td>
                                        <input type="checkbox" class="field-required-checkbox" data-field-id="<?php echo $field['id']; ?>" <?php echo $field['is_required'] ? 'checked' : ''; ?> />
                                    </td>
                                    <td>
                                        <?php if($field['is_deletable']): ?>
                                        <a href="#" data-ajax-action="delete_user_field" data-field-id="<?php echo $field['id']; ?>" class="btn btn-danger btn-sm ajax-delete-link" data-confirm="តើអ្នកពិតជាចង់លុប Field '<?php echo htmlspecialchars($field['field_label']); ?>' នេះមែនទេ?">
                                            <i class="fa-solid fa-trash-can"></i> លុប
                                        </a>
                                        <?php else: ?>
                                            <span style="color: #7f8c8d; font-style: italic;">(Default)</span>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endwhile;
                            } else {
                                echo '<tr><td colspan="4" style="text-align:center;">មិនទាន់មាន Field ណាមួយត្រូវបានបង្កើតទេ។</td></tr>';
                            }
                            $fields_stmt->close();
                            ?>
                        </tbody>
                     </table>

                <!-- START: បន្ថែមទំព័រថ្មីសម្រាប់គ្រប់គ្រង Fields សំណើរ -->
                <?php elseif ($settings_action === 'manage_request_fields' && hasPageAccess($mysqli, 'settings', 'manage_request_fields', $admin_id_check)): ?>
                    <h2><i class="fa-solid fa-clipboard-list"></i> គ្រប់គ្រង Fields សម្រាប់ទម្រង់សំណើរ</h2>
                    <p>កំណត់ Fields បន្ថែមសម្រាប់ទម្រង់ស្នើសុំនីមួយៗ (សុំច្បាប់, OT ។ល។) ដែលនឹងបង្ហាញនៅលើ App របស់ User។</p>

                    <div style="background: #ecf0f1; padding: 20px; border-radius: 8px; margin-bottom: 30px;">
                        <h3 style="margin-top:0"><i class="fa-solid fa-plus-circle"></i> បន្ថែម Field សំណើរថ្មី</h3>
                        <form id="addRequestFieldForm" class="ajax-form">
                            <input type="hidden" name="ajax_action" value="add_request_field">
                            <div style="display: flex; gap: 15px; align-items: flex-end; flex-wrap: wrap;">
                                <div class="form-group" style="flex: 2 1 250px;">
                                    <label>ឈ្មោះ Field (Label):</label>
                                    <input type="text" name="field_label" class="form-control" placeholder="ឧ. អ្នកទទួលខុសត្រូវជំនួស" required>
                                </div>
                                <div class="form-group" style="flex: 1 1 180px;">
                                    <label>ប្រភេទសំណើរ:</label>
                                    <select name="request_type" class="form-control">
                                        <option value="All">សម្រាប់គ្រប់សំណើរ</option>
                                        <option value="Leave">សម្រាប់តែ (Leave)</option>
                                        <option value="Overtime">សម្រាប់តែ (Overtime)</option>
                                        <option value="Forget-Attendance">សម្រាប់តែ (Forget)</option>
                                        <option value="Late">សម្រាប់តែ (Late)</option>
                                        <option value="Change-Day-Off">សម្រាប់តែ (Change Day Off)</option>
                                    </select>
                                </div>
    <div class="form-group" style="flex: 1 1 180px;">
                                    <label>ប្រភេទ Input:</label>
                                    <select name="field_type" class="form-control">
                                        <option value="text">Text (មួយបន្ទាត់)</option>
                                        <option value="textarea">Textarea (ច្រើនបន្ទាត់)</option>
                                        <option value="number">លេខ (Number)</option>
                                        <option value="date">កាលបរិច្ឆេទ (Date)</option>
                                        <option value="time">ពេលវេលា (Time)</option>
                                    </select>
                                </div>
                                <div class="form-group checkbox-item" style="margin-bottom: 10px; flex-shrink: 0;">
                                    <input type="checkbox" name="is_required" id="is_required_req" value="1">
                                    <label for="is_required_req">ត្រូវតែបំពេញ (Required)</label>
                                </div>
                                <div class="form-group" style="flex-shrink: 0;">
                                    <button type="submit" class="btn btn-success"><i class="fa-solid fa-plus"></i> បន្ថែម Field</button>
                                </div>
                            </div>
                        </form>
                    </div>

                    <h3><i class="fa-solid fa-list-ul"></i> Fields សំណើរដែលមានបច្ចុប្បន្ន</h3>
                     <table class="table">
                        <thead>
                            <tr><th>ឈ្មោះ Field (Label)</th><th>សម្រាប់សំណើរប្រភេទ</th><th>ប្រភេទ Input</th><th>Required?</th><th>Active?</th><th>សកម្មភាព</th></tr>
                        </thead>
                        <tbody>
                            <tbody>
                            <?php
                            $fields_stmt = $mysqli->prepare("SELECT * FROM request_form_fields WHERE admin_id = ? ORDER BY request_type ASC, id ASC");
                            $fields_stmt->bind_param("s", $current_admin_id);
                            $fields_stmt->execute();
                            $existing_fields = $fields_stmt->get_result();
                            if ($existing_fields && $existing_fields->num_rows > 0) {
                                $current_group = null; // Variable to track the current group

                                while($field = $existing_fields->fetch_assoc()):
                                    // Check if the group has changed
                                    if ($field['request_type'] !== $current_group) {
                                        $current_group = $field['request_type'];
                                        // Print a header row for the new group
                                        echo '<tr style="background-color: #e9ecef; font-weight: bold; color: var(--primary-color);">';
                                        echo '<td colspan="6"><i class="fa-solid fa-folder-open"></i> &nbsp;សម្រាប់សំណើរប្រភេទ: ' . htmlspecialchars($current_group) . '</td>';
                                        echo '</tr>';
                                    }
                                ?>
                                <tr>
                                    <td style="padding-left: 30px;"><?php echo htmlspecialchars($field['field_label']); ?><br><small style="color: #7f8c8d;">Key: <?php echo htmlspecialchars($field['field_key']); ?></small></td>
                                    <td><?php echo htmlspecialchars($field['field_type']); ?></td>
                                    <td><?php echo $field['is_required'] ? '<i class="fa-solid fa-check" style="color: green;"></i> Yes' : '<i class="fa-solid fa-times" style="color: red;"></i> No'; ?></td>
                                    <td>
                                        <label class="switch">
                                          <input type="checkbox" class="toggle-status-switch" data-field-id="<?php echo $field['id']; ?>" <?php echo ($field['is_active'] ?? 0) ? 'checked' : ''; ?>>
                                          <span class="slider round"></span>
                                        </label>
                                    </td>
                                    <td colspan="2"> <!-- Merged the last two columns for the action button -->
                                        <?php if($field['is_deletable']): ?>
                                        <a href="#" data-ajax-action="delete_request_field" data-field-id="<?php echo $field['id']; ?>" class="btn btn-danger btn-sm ajax-delete-link" data-confirm="តើអ្នកពិតជាចង់លុប Field '<?php echo htmlspecialchars($field['field_label']); ?>' នេះមែនទេ?">
                                            <i class="fa-solid fa-trash-can"></i> លុប
                                        </a>
                                        <?php endif; ?>
                                    </td>
                                </tr>
                                <?php endwhile;
                            } else {
                                echo '<tr><td colspan="6" style="text-align:center;">មិនទាន់មាន Field សម្រាប់សំណើរណាមួយត្រូវបានបង្កើតទេ។</td></tr>';
                            }
                            $fields_stmt->close();
                            ?>

                        </tbody>
                     </table>
                <!-- END: បន្ថែមទំព័រថ្មី -->

                  <!-- START: បន្ថែមកូដថ្មី -->
                <?php elseif ($settings_action === 'manage_app_scan' && hasPageAccess($mysqli, 'settings', 'manage_app_scan', $current_admin_id)): ?>
                    <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                        <h3 style="margin-top: 0;"><i class="fa-solid fa-mobile-screen-button"></i> ការកំណត់សម្រាប់ App Scan (scan.php)</h3>


                        <form id="appScanSettingsForm" class="ajax-form" enctype="multipart/form-data">
                            <input type="hidden" name="ajax_action" value="save_app_scan_settings">
                            <style>
                                .appscan-tabs{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 14px;}
                                .appscan-tab-btn{background:#f1f4f7;border:1px solid #d0d7de;padding:8px 14px;border-radius:6px;cursor:pointer;font-size:13px;font-weight:600;letter-spacing:.3px;color:#34495e;display:flex;align-items:center;gap:6px;transition:background .18s,color .18s,box-shadow .18s}
                                .appscan-tab-btn:hover{background:#e4eaef}
                                .appscan-tab-btn.active{background:#2563eb;color:#fff;border-color:#1d4ed8;box-shadow:0 2px 6px rgba(0,0,0,.08)}
                                .appscan-tab-panel{display:none}
                                .appscan-tab-panel.active{display:block}
                                .tab-divider{height:1px;background:#e2e8f0;margin:2px 0 16px;width:100%}
                                .appscan-tab-btn i{font-size:14px}
                            </style>
                            <div class="appscan-tabs" role="tablist" aria-label="App Scan Settings Tabs">
                                <button type="button" class="appscan-tab-btn active" data-tab="tab-header"><i class="fa-solid fa-window-maximize"></i> Header</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-vis-skill"><i class="fa-solid fa-eye"></i> Visibility (Skill)</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-vis-worker"><i class="fa-solid fa-eye"></i> Visibility (Worker)</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-labels-skill"><i class="fa-solid fa-font"></i> Labels (Skill)</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-labels-worker"><i class="fa-solid fa-font"></i> Labels (Worker)</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-telegram"><i class="fa-brands fa-telegram"></i> Telegram</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-departments"><i class="fa-solid fa-building"></i> Departments</button>
                                <button type="button" class="appscan-tab-btn" data-tab="tab-column-visibility"><i class="fa-solid fa-table-columns"></i> Column Visibility</button>
                            </div>
                            <script>
                                function toggleManualScanInput(selectEl, type) {
                                    var inputId = 'manual_scan_users_' + type;
                                    var inputEl = document.getElementById(inputId);
                                    if(selectEl.value === 'specific') {
                                        inputEl.style.display = 'block';
                                    } else {
                                        inputEl.style.display = 'none';
                                    }
                                }
                            </script>
                            <div class="tab-divider"></div>

                            <div id="tab-header" class="form-section appscan-tab-panel active">
                                <h4><i class="fa-solid fa-window-maximize"></i> ការកំណត់ Header</h4>
                                <div class="form-group">
                                    <label>ប្រភេទ Header:</label>
                                    <select name="header_type" class="form-control">
                                        <option value="title" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'header_type', 'title') == 'title') ? 'selected' : ''; ?>>បង្ហាញតែឈ្មោះ (Title)</option>
                                        <option value="logo" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'header_type', 'title') == 'logo') ? 'selected' : ''; ?>>បង្ហាញតែ Logo</option>
                                    </select>
                                </div>
                                <div class="form-group">
                                    <label>ឈ្មោះ (Title) Header:</label>
                                    <input type="text" name="header_title" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'header_title', 'Attendance App')); ?>">
                                </div>
                                <div class="form-group">
                                    <label>ចំណងជើងរង (Subtitle) Header:</label>
                                    <input type="text" name="header_subtitle" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'header_subtitle', '')); ?>" placeholder="Optional subtitle under main title">
                                </div>
                                <div class="form-group">
                                    <label>Upload Logo (នឹងបង្ហាញជំនួសឈ្មោះបើបានជ្រើសរើស):</label>
                                    <input type="file" name="header_logo" class="form-control" accept="image/png, image/jpeg, image/gif, image/svg+xml">
                                    <?php
                                    $current_logo = get_app_scan_setting($mysqli, $current_admin_id, 'header_logo_path', '');
                                    if (!empty($current_logo) && file_exists($current_logo)): ?>
                                        <div style="margin-top: 10px;">Logo បច្ចុប្បន្ន: <img src="<?php echo htmlspecialchars($current_logo); ?>" alt="Current App Logo" style="max-height: 40px; background: #ddd; padding: 5px; border-radius: 4px;"></div>
                                    <?php endif; ?>
                                </div>
                            </div>


                            <div id="tab-vis-skill" class="form-section appscan-tab-panel" style="border:1px dashed #dcdcdc; padding:12px; border-radius:8px; background:#f9fbfd;">
                                <h4 style="margin-top:0;"><i class="fa-solid fa-user-graduate"></i> Visibility Overrides (Skill)</h4>
                                <small class="text-muted" style="font-size:12px;">Fallback ទៅ Base បើមិនជ្រើស</small>
                                <div class="form-group" style="background:#e8fdf5; border:1px solid #10b981; padding:10px; border-radius:6px; margin-bottom:10px;">
                                    <label style="font-weight:bold; color:#047857; display:block; margin-bottom:5px;"><i class="fa-solid fa-hand-pointer"></i> ការកំណត់ស្កេនដៃ (Manual Scan)</label>
                                    <?php $skillMode = get_app_scan_setting($mysqli, $current_admin_id, 'manual_scan_mode__skill', 'disabled'); ?>
                                    <select name="manual_scan_mode__skill" class="form-control" style="margin-bottom:8px;" onchange="toggleManualScanInput(this, 'skill')">
                                        <option value="disabled" <?php echo ($skillMode == 'disabled') ? 'selected' : ''; ?>>បិទ (Disabled)</option>
                                        <option value="all" <?php echo ($skillMode == 'all') ? 'selected' : ''; ?>>បង្ហាញទាំងអស់ (All)</option>
                                        <option value="specific" <?php echo ($skillMode == 'specific') ? 'selected' : ''; ?>>ជ្រើសរើសបុគ្គលិក (Specific)</option>
                                    </select>
                                    <input type="text" id="manual_scan_users_skill" name="manual_scan_specific_users__skill" class="form-control"
                                           placeholder="ID បុគ្គលិក (ចែកដោយសញ្ញាក្បៀស , )"
                                           value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'manual_scan_specific_users__skill', '')); ?>"
                                           style="display: <?php echo ($skillMode == 'specific') ? 'block' : 'none'; ?>;">
                                </div>
                                <div class="checkbox-item"><input type="checkbox" name="show_attendance_card__skill" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_attendance_card__skill', '') == '1') ? 'checked' : ''; ?>> Attendance Card</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_request_form_card__skill" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_request_form_card__skill', '') == '1') ? 'checked' : ''; ?>> Request Form Card</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_my_requests_card__skill" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_my_requests_card__skill', '') == '1') ? 'checked' : ''; ?>> My Requests Card/Footer</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_view_logs_card__skill" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_view_logs_card__skill', '') == '1') ? 'checked' : ''; ?>> View Logs Card/Footer</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_profile_footer__skill" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_profile_footer__skill', '') == '1') ? 'checked' : ''; ?>> Profile Footer</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_home_footer__skill" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_home_footer__skill', '') == '1') ? 'checked' : ''; ?>> Home Footer</div>
                            </div>
                            <div id="tab-vis-worker" class="form-section appscan-tab-panel" style="border:1px dashed #dcdcdc; padding:12px; border-radius:8px; background:#f9fbfd;">
                                <h4 style="margin-top:0;"><i class="fa-solid fa-people-carry-box"></i> Visibility Overrides (Worker)</h4>
                                <small class="text-muted" style="font-size:12px;">Fallback ទៅ Base បើមិនជ្រើស</small>
                                <div class="form-group" style="background:#e8fdf5; border:1px solid #10b981; padding:10px; border-radius:6px; margin-bottom:10px;">
                                    <label style="font-weight:bold; color:#047857; display:block; margin-bottom:5px;"><i class="fa-solid fa-hand-pointer"></i> ការកំណត់ស្កេនដៃ (Manual Scan)</label>
                                    <?php $workerMode = get_app_scan_setting($mysqli, $current_admin_id, 'manual_scan_mode__worker', 'disabled'); ?>
                                    <select name="manual_scan_mode__worker" class="form-control" style="margin-bottom:8px;" onchange="toggleManualScanInput(this, 'worker')">
                                        <option value="disabled" <?php echo ($workerMode == 'disabled') ? 'selected' : ''; ?>>បិទ (Disabled)</option>
                                        <option value="all" <?php echo ($workerMode == 'all') ? 'selected' : ''; ?>>បង្ហាញទាំងអស់ (All)</option>
                                        <option value="specific" <?php echo ($workerMode == 'specific') ? 'selected' : ''; ?>>ជ្រើសរើសបុគ្គលិក (Specific)</option>
                                    </select>
                                    <input type="text" id="manual_scan_users_worker" name="manual_scan_specific_users__worker" class="form-control"
                                           placeholder="ID បុគ្គលិក (ចែកដោយសញ្ញាក្បៀស , )"
                                           value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'manual_scan_specific_users__worker', '')); ?>"
                                           style="display: <?php echo ($workerMode == 'specific') ? 'block' : 'none'; ?>;">
                                </div>
                                <div class="checkbox-item"><input type="checkbox" name="show_attendance_card__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_attendance_card__worker', '') == '1') ? 'checked' : ''; ?>> Attendance Card</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_request_form_card__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_request_form_card__worker', '') == '1') ? 'checked' : ''; ?>> Request Form Card</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_my_requests_card__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_my_requests_card__worker', '') == '1') ? 'checked' : ''; ?>> My Requests Card/Footer</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_view_logs_card__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_view_logs_card__worker', '') == '1') ? 'checked' : ''; ?>> View Logs Card/Footer</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_profile_footer__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_profile_footer__worker', '') == '1') ? 'checked' : ''; ?>> Profile Footer</div>
                                <div class="checkbox-item"><input type="checkbox" name="show_home_footer__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_home_footer__worker', '') == '1') ? 'checked' : ''; ?>> Home Footer</div>
                            </div>


                            <div id="tab-labels-skill" class="form-section appscan-tab-panel" style="border:1px dashed #dcdcdc; padding:12px; border-radius:8px; background:#f4f8fa;">
                                <h4 style="margin-top:0;"><i class="fa-solid fa-user-graduate"></i> Label Overrides (Skill)</h4>
                                <div class="form-group"><label>Greeting (Skill):</label><input type="text" name="greeting_text__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'greeting_text__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Attendance Label (Skill):</label><input type="text" name="label_attendance__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_attendance__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Request Form Label (Skill):</label><input type="text" name="label_request_form__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_request_form__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>My Requests Label (Skill):</label><input type="text" name="label_my_requests__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_my_requests__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>View Logs Label (Skill):</label><input type="text" name="label_view_logs__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_view_logs__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Profile Label (Skill):</label><input type="text" name="label_profile__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_profile__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Header Title (Skill):</label><input type="text" name="header_title__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'header_title__skill', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Header Subtitle (Skill):</label><input type="text" name="header_subtitle__skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'header_subtitle__skill', '')); ?>" placeholder="Fallback: Base"></div>
                            </div>
                            <div id="tab-labels-worker" class="form-section appscan-tab-panel" style="border:1px dashed #dcdcdc; padding:12px; border-radius:8px; background:#f4f8fa;">
                                <h4 style="margin-top:0;"><i class="fa-solid fa-people-carry-box"></i> Label Overrides (Worker)</h4>
                                <div class="form-group"><label>Greeting (Worker):</label><input type="text" name="greeting_text__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'greeting_text__worker', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Attendance Label (Worker):</label><input type="text" name="label_attendance__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_attendance__worker', '')); ?>"></div>
                                <div class="form-group"><label>Request Form Label (Worker):</label><input type="text" name="label_request_form__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_request_form__worker', '')); ?>"></div>
                                <div class="form-group"><label>My Requests Label (Worker):</label><input type="text" name="label_my_requests__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_my_requests__worker', '')); ?>"></div>
                                <div class="form-group"><label>View Logs Label (Worker):</label><input type="text" name="label_view_logs__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_view_logs__worker', '')); ?>"></div>
                                <div class="form-group"><label>Profile Label (Worker):</label><input type="text" name="label_profile__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'label_profile__worker', '')); ?>"></div>
                                <div class="form-group"><label>Header Title (Worker):</label><input type="text" name="header_title__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'header_title__worker', '')); ?>"></div>
                                <div class="form-group"><label>Header Subtitle (Worker):</label><input type="text" name="header_subtitle__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'header_subtitle__worker', '')); ?>"></div>
                            </div>

                            <div id="tab-telegram" class="form-section appscan-tab-panel">
                                <h4><i class="fa-solid fa-paper-plane"></i> ការកំណត់ Telegram</h4>
                                <p style="font-size:13px;" class="text-muted">បំពេញ Bot Token និង Chat ID ដើម្បីអាចផ្ញើសារជូនដំណឹងពីវត្តមាន និង សំណើរ។ <strong>សុវត្ថិភាព៖</strong> Token នឹងរក្សាទុកក្នុងមូលដ្ឋានទិន្នន័យ (ចូលបានតែ Admin នេះ). កុំប្រើ Bot Token ដែលមានសិទ្ធិអរូបីផ្សេងៗ។</p>
                                <div class="form-group">
                                    <label>Bot Token:</label>
                                    <input type="text" name="telegram_bot_token" class="form-control" placeholder="123456789:ABCDEF-Token" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'telegram_bot_token', '')); ?>">
                                </div>
                                <div class="form-group">
                                    <label>Chat ID / Channel ID:</label>
                                    <input type="text" name="telegram_chat_id" class="form-control" placeholder="ឧ. 123456789 ឬ -100XXXXXXXXXX" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'telegram_chat_id', '')); ?>">
                                </div>
                                <div class="checkbox-item"><input type="checkbox" name="telegram_notify_attendance" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'telegram_notify_attendance', '0') == '1') ? 'checked' : ''; ?>> ផ្ញើសារ ពេល Check-In/Out</div>
                                <div class="checkbox-item"><input type="checkbox" name="telegram_notify_requests" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'telegram_notify_requests', '0') == '1') ? 'checked' : ''; ?>> ផ្ញើសារ ពេលមាន Request ថ្មី</div>
                                <hr style="margin:14px 0;">
                                <!-- Removed Telegram Overrides for Skill (base fields already handle this). -->
                                <h5 style="margin-top:16px;"><i class="fa-solid fa-people-carry-box"></i> Telegram Overrides (Worker)</h5>
                                <div class="form-group"><label>Bot Token (Worker):</label><input type="text" name="telegram_bot_token__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'telegram_bot_token__worker', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="form-group"><label>Chat/Channel ID (Worker):</label><input type="text" name="telegram_chat_id__worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'telegram_chat_id__worker', '')); ?>" placeholder="Fallback: Base"></div>
                                <div class="checkbox-item"><input type="checkbox" name="telegram_notify_attendance__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'telegram_notify_attendance__worker', '') == '1') ? 'checked' : ''; ?>> Notify Attendance (Worker)</div>
                                <div class="checkbox-item"><input type="checkbox" name="telegram_notify_requests__worker" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'telegram_notify_requests__worker', '') == '1') ? 'checked' : ''; ?>> Notify Requests (Worker)</div>
                                <div class="form-group" style="margin-top:10px;">
                                    <label>ទម្រង់ថ្ងៃ/ម៉ោង សម្រាប់ Placeholder <code>{{time}}</code>:</label>
                                    <?php
                                    // Preset formats (PHP date compatible)
                                    $formats = [
                                        'Y-m-d H:i:s' => date('Y-m-d H:i:s'),
                                        'd/m/Y H:i:s' => date('d/m/Y H:i:s'),
                                        'd-m-Y h:i A' => date('d-m-Y h:i A'),
                                        'M j, Y g:i A' => date('M j, Y g:i A'),
                                        'd F Y H:i'   => date('d F Y H:i'),
                                        'j M Y, H:i'  => date('j M Y, H:i')
                                    ];
                                    $current_tf = get_app_scan_setting($mysqli, $current_admin_id, 'telegram_time_format', 'Y-m-d H:i:s');
                                    $is_custom_tf = !array_key_exists($current_tf, $formats);
                                    ?>
                                    <div style="display:flex; gap:8px; flex-wrap:wrap;">
                                        <select name="telegram_time_format_preset" class="form-control" style="flex:1; min-width:220px;" aria-label="Preset time format">
                                            <?php foreach ($formats as $fmt => $sample):
                                                $sel = (!$is_custom_tf && $fmt === $current_tf) ? 'selected' : '';
                                                $safeSample = addslashes($sample);
                                            ?>
                                                <option value="<?php echo htmlspecialchars($fmt); ?>" data-sample="<?php echo $safeSample; ?>" <?php echo $sel; ?>><?php echo htmlspecialchars($fmt . ' — ' . $sample); ?></option>
                                            <?php endforeach; ?>
                                            <option value="__custom__" <?php echo $is_custom_tf ? 'selected' : ''; ?>>Custom...</option>
                                        </select>
                                        <input type="text" name="telegram_time_format" id="telegram_time_format_custom" class="form-control" style="flex:1; min-width:220px;" placeholder="ឧ. d-m-Y h:i A — Custom" value="<?php echo htmlspecialchars($current_tf); ?>" aria-label="Custom time format">
                                    </div>
                                    <small class="form-text" style="color:#7f8c8d;">
                                        • ប្រើ Preset ឬ កែ <strong>Custom</strong> ដោយផ្ទាល់ (PHP <code>date()</code> format). អ្នកអាចបន្ថែមអត្ថបទថេរ (" — Late Scan") ដោយសរសេរតាមក្រោយ Pattern។<br>
                                        • Example: <code>d-m-Y h:i A — Phnom Penh</code> នឹងបញ្ជូន <code><?php echo date('d-m-Y h:i A'); ?> — Phnom Penh</code>
                                    </small>
                                </div>
                                <small style="display:block; margin-top:8px; color:#7f8c8d;">បើមិនដាក់ Token/chat id ឬមិនติ๊ก enable ទេ សារ Telegram នឹងមិនត្រូវបានផ្ញើ។</small>
                                <hr>
                                <h5 style="margin: 12px 0 8px;">គំរូសារ (Message Templates)</h5>
                                <p style="font-size:12px; color:#7f8c8d; margin-top:-6px;">អ្នកអាចប្រើ Placeholder ដូចជា: <code>{{name}}</code>, <code>{{employee_id}}</code>, <code>{{action}}</code>, <code>{{status}}</code>, <code>{{status_icon}}</code>, <code>{{time}}</code>, <code>{{location_name}}</code>, <code>{{distance_m}}</code>, <code>{{allowed_distance}}</code>, <code>{{late_reason}}</code>, <code>{{late_reason_section}}</code>, <code>{{map_url}}</code> សម្រាប់វត្តមាន; និង <code>{{request_type}}</code>, <code>{{summary}}</code> សម្រាប់សំណើរ។<br><strong>{{late_reason}}</strong> ផ្តល់តែអត្ថបទមូលហេតុត្រង់ៗ (គ្មានស្លាក); ប្រសិនបើត្រូវការ​ឲ្យលាក់ទូទៅពេលទទេ សូមប្រើ <strong>{{late_reason_section}}</strong> ដែលនឹងបង្ហាញជា "<b>មូលហេតុ:</b> ..." ប្រសិនបើមានតែប៉ុណ្ណោះ។<br>បន្ថែមទៀត អ្នកអាចប្រើ <code>{{field_department}}</code>, <code>{{field_position}}</code>, ... ជា <strong>{{field_<em>field_key</em>}}</strong> ដើម្បីយកតម្លៃពី Custom Data របស់បុគ្គលិក។ (Field Key មកពី Column <code>field_key</code> នៅក្នុងតារាង user_form_fields / custom_data JSON)</p>
                                <div class="form-group" style="display:flex; gap:20px; flex-wrap:wrap; align-items:flex-end;">
                                    <div style="flex:1; min-width:200px;">
                                        <label>Icon សម្រាប់ Status Good:</label>
                                        <input type="text" name="status_icon_good" class="form-control" maxlength="8" placeholder="ឧ. ✅ ឬ 🔵" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'status_icon_good', '🔵')); ?>">
                                        <small class="form-text" style="color:#7f8c8d;">អាចជាអ៊ីមូជី ឬ តួអក្សរ (&lt;= 2–3 glyph)</small>
                                    </div>
                                    <div style="flex:1; min-width:200px;">
                                        <label>Icon សម្រាប់ Status Late:</label>
                                        <input type="text" name="status_icon_late" class="form-control" maxlength="8" placeholder="ឧ. ⚠️ ឬ 🔴" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'status_icon_late', '🔴')); ?>">
                                        <small class="form-text" style="color:#7f8c8d;">ប្រើអ៊ីមូជីដែលងាយមើលឃើញ</small>
                                    </div>
                                    <div style="flex:100%;"></div>
                                </div>
                                <div class="form-group">
                                    <label>Template សារ វត្តមាន (Attendance):</label>
                                    <?php
                                    // Build a smart default template that includes placeholders for any custom fields
                                    $stored_tpl = get_app_scan_setting($mysqli, $current_admin_id, 'telegram_tpl_attendance', '');
                                    if (trim($stored_tpl) === '') {
                                        $base = "<b>[ATTENDANCE]</b>\n<b>ឈ្មោះ:</b> {{name}}\n<b>ID:</b> {{employee_id}}\n<b>សកម្មភាព:</b> {{action}} ({{status_icon}} {{status}})\n<b>ម៉ោង:</b> {{time}}\n<b>ទីតាំង:</b> {{location_name}}\n<b>ចំងាយ:</b> {{distance_m}} ({{distance_status}})\n{{late_reason_section}}\n{{map_url}}";

                                        // Collect field keys and labels from user_form_fields for this admin
                                        $field_map = [];
                                        if ($fs = $mysqli->prepare("SELECT field_key, field_label FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC")) {
                                            $fs->bind_param('s', $current_admin_id);
                                            if ($fs->execute()) {
                                                $resf = $fs->get_result();
                                                while ($r = $resf->fetch_assoc()) {
                                                    $k = trim($r['field_key']);
                                                    if ($k !== '') { $field_map[$k] = $r['field_label'] ?: $k; }
                                                }
                                            }
                                            $fs->close();
                                        }

                                        // Also scan existing users.custom_data to discover any ad-hoc keys
                                        $extra_keys = [];
                                        if ($us = $mysqli->prepare("SELECT custom_data FROM users WHERE created_by_admin_id = ?")) {
                                            $us->bind_param('s', $current_admin_id);
                                            if ($us->execute()) {
                                                $resu = $us->get_result();
                                                while ($ur = $resu->fetch_assoc()) {
                                                    $cd = json_decode($ur['custom_data'] ?? '{}', true);
                                                    if (is_array($cd)) {
                                                        foreach ($cd as $ck => $cv) { if (!isset($field_map[$ck])) { $extra_keys[$ck] = $ck; } }
                                                    }
                                                }
                                            }
                                            $us->close();
                                        }

                                        // Build additional placeholder lines
                                        $additional = "\n\n<b>Additional fields from Custom Data:</b>\n";
                                        $has_add = false;
                                        foreach ($field_map as $fk => $flabel) {
                                            $additional .= "<b>" . $flabel . ":</b> {{field_" . $fk . "}}\n";
                                            $has_add = true;
                                        }
                                        foreach ($extra_keys as $ek) {
                                            $additional .= "<b>" . $ek . ":</b> {{field_" . $ek . "}}\n";
                                            $has_add = true;
                                        }
                                        if ($has_add) { $stored_tpl = $base . $additional; } else { $stored_tpl = $base; }
                                    }
                                    ?>
                                    <textarea id="tpl_attendance" name="telegram_tpl_attendance" class="form-control" rows="6" placeholder="Template សម្រាប់វត្តមាន..."><?php echo htmlspecialchars($stored_tpl); ?></textarea>
                                    <div style="margin-top:6px; display:flex; align-items:center; gap:10px;">
                                        <label style="margin:0; font-size:13px; color:#667;">
                                            <input type="checkbox" class="toggle-template-preview" data-target="#tpl_attendance_preview"> បង្ហាញ Preview (មើលដោយគ្មានអក្សរកូដ)
                                        </label>
                                        <button type="button" class="btn btn-sm" style="background:#ecf0f1;" onclick="insertPlaceholder('tpl_attendance')"><i class="fa-solid fa-plus"></i> Placeholder</button>
                                    </div>
                                    <div id="tpl_attendance_preview" class="template-preview-box" style="display:none;"></div>
                                </div>
                                <div class="form-group">
                                    <label>Template សារ សំណើរ (Request):</label>
                                    <textarea id="tpl_request" name="telegram_tpl_request" class="form-control" rows="6" placeholder="Template សម្រាប់សំណើរ..."><?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'telegram_tpl_request', "<b>[NEW REQUEST]</b>\n<b>ប្រភេទ:</b> {{request_type}}\n<b>ឈ្មោះ:</b> {{name}}\n<b>ID:</b> {{employee_id}}\n<b>ព័ត៌មានលម្អិត:</b> {{summary}}\n<b>ម៉ោង:</b> {{time}}")); ?></textarea>
                                    <div style="margin-top:6px; display:flex; align-items:center; gap:10px;">
                                        <label style="margin:0; font-size:13px; color:#667;">
                                            <input type="checkbox" class="toggle-template-preview" data-target="#tpl_request_preview"> បង្ហាញ Preview (មើលដោយគ្មានអក្សរកូដ)
                                        </label>
                                        <button type="button" class="btn btn-sm" style="background:#ecf0f1;" onclick="insertPlaceholder('tpl_request')"><i class="fa-solid fa-plus"></i> Placeholder</button>
                                    </div>
                                    <div id="tpl_request_preview" class="template-preview-box" style="display:none;"></div>
                                </div>
                            </div>

                            <div id="tab-departments" class="form-section appscan-tab-panel">
                                <h4><i class="fa-solid fa-building"></i> Allow Departments (Skill / Worker)</h4>
                                <p class="text-muted" style="font-size:12px;">Comma-separated list of departments/workplaces allowed per type. Empty = allow all.</p>
                                <div class="form-group"><label>Allowed Departments សម្រាប់ Skill:</label><input type="text" name="allowed_departments_skill" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'allowed_departments_skill', '')); ?>" placeholder="Finance,HR,IT"></div>
                                <div class="form-group"><label>Allowed Departments សម្រាប់ Worker:</label><input type="text" name="allowed_departments_worker" class="form-control" value="<?php echo htmlspecialchars(get_app_scan_setting($mysqli, $current_admin_id, 'allowed_departments_worker', '')); ?>" placeholder="Factory A,Factory B"></div>
                            </div>

                            <div id="tab-column-visibility" class="form-section appscan-tab-panel">
                                <h4><i class="fa-solid fa-table-columns"></i> Column Visibility Settings</h4>
                                <p class="text-muted" style="font-size:12px;">Configure which columns to show/hide in the detailed attendance reports table.</p>

                                <div class="column-visibility-grid">
                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_checkbox" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_checkbox', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Checkbox (ជ្រើសរើស)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_employee_id" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_employee_id', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Employee ID (អត្តលេខ)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_name" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_name', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Name (ឈ្មោះ)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_action_type" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_action_type', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Action Type (សកម្មភាព)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_date" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_date', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Date (ថ្ងៃខែឆ្នាំ)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_time" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_time', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Time (ពេលវេលា)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_status" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_status', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Status (ស្ថានភាព)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_late_reason" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_late_reason', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Late Reason (មូលហេតុ)</span>
                                        </label>
                                    </div>

                                    <div class="column-visibility-item">
                                        <label class="column-visibility-label">
                                            <input type="checkbox" name="show_column_actions" value="1" <?php echo (get_app_scan_setting($mysqli, $current_admin_id, 'show_column_actions', '1') == '1') ? 'checked' : ''; ?>>
                                            <span>Actions (សកម្មភាព)</span>
                                        </label>
                                    </div>
                                </div>

                                <div class="form-group" style="margin-top: 20px;">
                                    <label><i class="fa-solid fa-gear"></i> Dynamic Fields Visibility:</label>
                                    <div class="dynamic-fields-visibility">
                                        <?php
                                        $fields_stmt = $mysqli->prepare("SELECT id, field_label FROM user_form_fields WHERE admin_id = ? ORDER BY field_order ASC");
                                        $fields_stmt->bind_param("s", $current_admin_id);
                                        $fields_stmt->execute();
                                        $fields_result = $fields_stmt->get_result();

                                        if ($fields_result && $fields_result->num_rows > 0) {
                                            while ($field = $fields_result->fetch_assoc()) {
                                                $field_id = $field['id'];
                                                $field_label = htmlspecialchars($field['field_label']);
                                                $setting_key = "show_dynamic_field_{$field_id}";
                                                $is_checked = (get_app_scan_setting($mysqli, $current_admin_id, $setting_key, '1') == '1') ? 'checked' : '';
                                                echo "<div class='column-visibility-item'>";
                                                echo "<label class='column-visibility-label'>";
                                                echo "<input type='checkbox' name='{$setting_key}' value='1' {$is_checked}>";
                                                echo "<span>{$field_label}</span>";
                                                echo "</label>";
                                                echo "</div>";
                                            }
                                        } else {
                                            echo "<p class='text-muted'>No custom fields configured.</p>";
                                        }
                                        $fields_stmt->close();
                                        ?>
                                    </div>
                                </div>
                            </div>

                            <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 20px;"><i class="fa-solid fa-save"></i> រក្សាទុកការកំណត់ App Scan</button>
                        </form>
                        <script>
                        (function(){
                            var form = document.getElementById('appScanSettingsForm');
                            if(!form) return;
                            var tabs = form.querySelectorAll('.appscan-tab-btn');
                            var panels = form.querySelectorAll('.appscan-tab-panel');
                            function show(tab){
                                tabs.forEach(function(b){ var on = b.dataset.tab === tab; b.classList.toggle('active', on); b.setAttribute('aria-selected', on ? 'true' : 'false'); });
                                panels.forEach(function(p){ p.classList.toggle('active', p.id === tab); });
                            }
                            tabs.forEach(function(b){ b.addEventListener('click', function(ev){ ev.preventDefault(); show(b.dataset.tab); }); });
                        })();
                        </script>
                    </div>


                <!-- END: បន្ថែមកូដថ្មី -->

                <?php elseif ($settings_action === 'login_page_settings' && hasPageAccess($mysqli, 'settings', 'login_page_settings', $admin_id_check)):
                    $current_login_title = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_title', 'Admin Panel Login');
                    $current_login_logo = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_logo_path', '');
                    $current_login_icon = get_setting($mysqli, 'SYSTEM_WIDE', 'login_page_icon_class', 'fa-solid fa-user-shield');
                ?>
                    <div style="background: white; padding: 20px; border-radius: 8px; box-shadow: 0 0 5px rgba(0,0,0,0.05); margin-bottom: 30px;">
                        <h3 style="margin-top: 0;"><i class="fa-solid fa-right-to-bracket"></i> ការកំណត់ Login Page</h3>
                        <p class="alert alert-info"><i class="fa-solid fa-info-circle"></i> ការកំណត់នេះនឹងផ្លាស់ប្តូររូបរាងទំព័រ Login សម្រាប់អ្នកប្រើប្រាស់ទាំងអស់។ មានតែ Super Admin ប៉ុណ្ណោះដែលអាចកែប្រែបាន។</p>

                        <form id="loginPageSettingsForm" class="ajax-form" enctype="multipart/form-data">
                            <input type="hidden" name="ajax_action" value="save_login_page_settings">

                            <div class="form-group">
                                <label for="login_page_title"><i class="fa-solid fa-pen-to-square"></i> ចំណងជើងទំព័រ Login:</label>
                                <input type="text" id="login_page_title" name="login_page_title" class="form-control" value="<?php echo htmlspecialchars($current_login_title); ?>">
                            </div>

                            <div class="form-group">
                                <label for="login_page_logo"><i class="fa-solid fa-image"></i> Logo សម្រាប់ទំព័រ Login (ទុកឱ្យទំនេរ បើមិនចង់ប្តូរ):</label>
                                <input type="file" id="login_page_logo" name="login_page_logo" class="form-control" accept="image/png, image/jpeg, image/gif, image/svg+xml">
                                <?php if (!empty($current_login_logo) && file_exists($current_login_logo)): ?>
                                    <div style="margin-top: 10px;">Logo បច្ចុប្បន្ន: <img src="<?php echo htmlspecialchars($current_login_logo); ?>" alt="Current Login Logo" style="max-height: 60px; background: #f0f0f0; padding: 5px; border-radius: 4px;"></div>
                                <?php endif; ?>
                            </div>

                            <div class="form-group">
                                <label for="login_page_icon_class"><i class="fa-brands fa-font-awesome"></i> Font Awesome Icon Class (បើគ្មាន Logo):</label>
                                <input type="text" id="login_page_icon_class" name="login_page_icon_class" class="form-control" value="<?php echo htmlspecialchars($current_login_icon); ?>" placeholder="ឧ. fa-solid fa-building-shield">
                                <small class="form-text">ប្រើ Icon នេះប្រសិនបើគ្មានការ Upload Logo ទេ។ អាចរក Class បានពី <a href="https://fontawesome.com/search?o=r&m=free" target="_blank">Font Awesome</a>។</small>
                            </div>

                            <button type="submit" class="btn btn-primary"><i class="fa-solid fa-save"></i> រក្សាទុកការកំណត់ Login Page</button>
                        </form>
                    </div>
                <?php else: ?>
                     <div class="alert alert-danger"><i class="fa-solid fa-lock"></i> **ការបដិសេធសិទ្ធិ:** អ្នកមិនមានសិទ្ធិចូលប្រើមុខងារនេះទេ។</div>
                <?php endif; ?>
            <?php endif; ?>

        </div>
    </div>

    <div class="footer">
        <?php echo $footer_text; ?>
    </div>
</div>

<div id="qrModal" class="modal">
	<span class="close" onclick="document.getElementById('qrModal').style.display='none'">&times;</span>
	<div class="modal-content" style="text-align: center;">
		<h3 id="qr-modal-title">QR Code សម្រាប់ទាញយក</h3>
		<img id="qr-image-display" src="" alt="QR Code Large">
		<a id="download-link" href="#" class="btn btn-success download-btn-modal" download="QR_Code_Location.png">
			<i class="fa-solid fa-download"></i> ទាញយក (PNG 500x500)
		</a>
	</div>
</div>

<!-- QR Designer Modal -->
<div id="qrDesignerModal" class="modal" style="display:none;">
    <div class="modal-content">
        <div class="modal-header" style="background-color:#8e44ad;">
            <h3 style="margin:0;"><i class="fa-solid fa-wand-magic-sparkles"></i> QR Designer</h3>
        </div>
        <div class="modal-body">
            <div class="form-group">
                <label>Location:</label>
                <input type="text" id="qrDesignLocationName" class="form-control" readonly>
            </div>
            <div class="form-group" style="display:flex; gap:15px; flex-wrap:wrap;">
                <div style="flex:1; min-width:220px;">
                    <label>Body Style</label>
                    <select id="qrBodyShape" class="form-control">
                        <option value="square">Square</option>
                        <option value="dots" selected>Dots</option>
                        <option value="rounded">Rounded</option>
                    </select>
                </div>
                <div style="flex:1; min-width:220px;">
                    <label>Eye Border Style</label>
                    <select id="qrEyeOuter" class="form-control">
                        <option value="square">Square</option>
                        <option value="dot" selected>Dot</option>
                    </select>
                </div>
                <div style="flex:1; min-width:220px;">
                    <label>Eye Center Style</label>
                    <select id="qrEyeInner" class="form-control">
                        <option value="square">Square</option>
                        <option value="dot" selected>Dot</option>
                    </select>
                </div>
            </div>

            <div class="form-group" style="margin-top:10px;">
                <label>Center Logo (optional)</label>
                <input type="file" id="qrLogoInput" accept="image/*" class="form-control">
                <small class="form-text text-muted">Use a transparent PNG for best results.</small>
            </div>

            <div id="qrPreview" style="margin-top:15px; display:flex; justify-content:center; align-items:center; min-height:260px; border:1px dashed #ccc; border-radius:8px; padding:10px;"></div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn" style="background:#95a5a6; color:white;" onclick="document.getElementById('qrDesignerModal').style.display='none'">បិទ</button>
            <button type="button" class="btn btn-success" id="qrDownloadPngBtn"><i class="fa-solid fa-download"></i> ទាញយក PNG</button>
            <button type="button" class="btn btn-primary" id="qrDownloadSvgBtn"><i class="fa-solid fa-file-code"></i> ទាញយក SVG</button>
        </div>
    </div>
</div>

<div id="editUserModal" class="modal">
	<div class="modal-content">
        <div class="modal-header" style="background-color: #2ecc71;">
		    <h3 style="color: white;"><i class="fa-solid fa-user-pen"></i> កែសម្រួលព័ត៌មានបុគ្គលិក</h3>
        </div>
        <div class="modal-body">
             <!-- Content will be loaded by AJAX -->
            <div id="editUserFormContainer">
                <p style="text-align: center;"><i class="fa-solid fa-spinner fa-spin"></i> Loading user data...</p>
            </div>
        </div>
	</div>
</div>

<div id="lateReasonModal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3><i class="fa-solid fa-comment-dots"></i> មូលហេតុ (Late Reason)</h3>
        </div>
        <div class="modal-body">
            <input type="hidden" id="late_reason_log_id">
            <div class="form-group">
                <label for="late_reason_text"><i class="fa-solid fa-pen"></i> កែប្រែមូលហេតុ</label>
                <textarea id="late_reason_text" class="form-control" rows="5" placeholder="សូមបញ្ចូលមូលហេតុ..."></textarea>
                <div class="form-text">អ្នកអាចទុកទទេបើមិនចង់បញ្ជាក់មូលហេតុ។</div>
            </div>
        </div>
        <div class="modal-footer">
            <button type="button" class="btn" style="background-color: #95a5a6; color: white;" onclick="$('#lateReasonModal').hide()">បិទ</button>
            <button type="button" id="saveLateReasonBtn" class="btn btn-primary"><i class="fa-solid fa-save"></i> រក្សាទុក</button>
        </div>
    </div>
 </div>

<div id="editLocationModal" class="modal">
	<span class="close" onclick="document.getElementById('editLocationModal').style.display='none'">&times;</span>
	<div class="modal-content">
        <div class="modal-header">
		    <h3><i class="fa-solid fa-map-pin"></i> កែសម្រួលព័ត៌មេ័យទីតាំង</h3>
        </div>
        <div class="modal-body">
            <form id="editLocationForm" class="ajax-form">
                <input type="hidden" name="ajax_action" value="update_location">
                <input type="hidden" name="edit_loc_id" id="edit_loc_id">
                <div class="form-group"><label><i class="fa-solid fa-map-pin"></i> ឈ្មោះទីតាំង:</label><input type="text" name="edit_loc_name" id="edit_loc_name" class="form-control" required></div>
                <div style="display: flex; gap: 20px;">
                    <div class="form-group" style="flex: 1;"><label><i class="fa-solid fa-globe"></i> Latitude:</label><input type="text" name="edit_latitude" id="edit_latitude" class="form-control" required></div>
                    <div class="form-group" style="flex: 1;"><label><i class="fa-solid fa-globe"></i> Longitude:</label><input type="text" name="edit_longitude" id="edit_longitude" class="form-control" required></div>
                </div>
                <div class="form-group"><label><i class="fa-solid fa-bullseye"></i> រង្វង់ (ម៉ែត្រ):</label><input type="number" name="edit_radius_meters" id="edit_radius_meters" class="form-control" min="10" required></div>
                <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 15px;"><i class="fa-solid fa-save"></i> រក្សាទុកការកែសម្រួលទីតាំង</button>
            </form>
        </div>
	</div>
</div>

<!-- Duplicate User Modal -->
<div id="duplicateUserModal" class="modal">
    <div class="modal-content">
        <div class="modal-header" style="background-color: #3498db;">
            <h3 style="color: white;"><i class="fa-solid fa-clone"></i> ចម្លងអ្នកប្រើប្រាស់</h3>
        </div>
        <div class="modal-body">
            <form id="duplicateUserForm" class="ajax-form">
                <input type="hidden" name="ajax_action" value="duplicate_user">
                <div class="form-group">
                    <label><i class="fa-solid fa-user"></i> User ដើម (មិនអាចកែបាន)</label>
                    <input type="text" id="dup_src_display" class="form-control" disabled>
                    <input type="hidden" name="src_id" id="dup_src_id">
                </div>
                <div class="form-group"><label><i class="fa-solid fa-id-card-clip"></i> ID ថ្មី:</label><input type="text" name="new_id" id="dup_new_id" class="form-control" required></div>
                <div class="form-group"><label><i class="fa-solid fa-signature"></i> ឈ្មោះថ្មី (បើទុកទទេ នឹងយកពីដើម + "(Copy)"):</label><input type="text" name="new_name" id="dup_new_name" class="form-control"></div>
                <div class="form-group" style="display:flex; gap: 12px; align-items:center;">
                    <label style="margin:0;">ជម្រើសចម្លង:</label>
                    <label><input type="checkbox" name="copy_rules" value="1" checked> ច្បាប់ម៉ោង</label>
                    <label><input type="checkbox" name="copy_locations" value="1" checked> កំណត់ទីតាំង</label>
                </div>
                <button type="submit" class="btn btn-primary" style="width: 100%;"><i class="fa-solid fa-clone"></i> ចម្លង</button>
            </form>
        </div>
    </div>
 </div>

<div id="requestDetailModal" class="modal">
	<div class="modal-content">
        <div class="modal-header">
		    <h3><i class="fa-solid fa-file-lines"></i> ពត៌មានលំអិតនៃសំណើរ #<span id="modal_req_id_display"></span></h3>
        </div>
        <div class="modal-body">
            <input type="hidden" id="modal_req_id">
            <div class="detail-grid">
                <div>ឈ្មោះបុគ្គលិក</div><div id="modal_req_name"></div>
                <div>អត្តលេខ</div><div id="modal_req_employee_id"></div>
                <div>ប្រភេទសំណើរ</div><div id="modal_req_type"></div>
                <div>ស្ថានភាព</div><div id="modal_req_status"></div>
                <div>ថ្ងៃដាក់ស្នើ</div><div id="modal_req_submitted"></div>
                <div>ថ្ងៃព្រឹត្តិការណ៍</div><div id="modal_req_event_date"></div>
            </div>
            <!-- Placeholder for Custom Data -->
            <div id="modal_req_custom_data_container"></div>

            <h4 style="margin-top: 20px; margin-bottom: 5px; color: #34495e;"><i class="fa-solid fa-comment-dots"></i> មូលហេតុលម្អិត</h4>
            <div id="modal_req_reason" class="reason-box"></div>
        </div>
        <div class="modal-footer" id="modal_req_footer">
            <button type="button" class="btn" style="background-color: #95a5a6; color: white;" onclick="document.getElementById('requestDetailModal').style.display='none'">បិទ</button>
            <button type="button" class="btn btn-danger" onclick="handleRequestAction('Rejected')"><i class="fa-solid fa-times-circle"></i> បដិសេធ (Reject)</button>
            <button type="button" class="btn btn-success" onclick="handleRequestAction('Approved')"><i class="fa-solid fa-check-circle"></i> យល់ព្រម (Approve)</button>
        </div>
	</div>
</div>

<script>
// Employment status update + revoke tokens helpers
function updateEmploymentStatus(empId, status, leaveDate){
    try {
        var fd = new FormData();
        fd.append('ajax_action','update_user_status');
        fd.append('employee_id', empId);
        fd.append('employment_status', status);
        if (leaveDate) fd.append('leave_date', leaveDate);
        fetch('admin_attendance.php', { method:'POST', body:fd, credentials:'same-origin' })
            .then(r=>r.json()).then(function(j){
                if(j.status!=='success'){ alert(j.message||'Update failed'); return; }
                // Soft refresh: update badge color inline
                var row = Array.from(document.querySelectorAll('#usersTableBody tr.user-row')).find(function(tr){ return tr.querySelector('.user-name-cell'); });
                // no-op: keep lightweight; optionally reload
            }).catch(function(e){ alert('Network error: '+e); });
    } catch(e){ alert('Error: '+e); }
}
// revokeUserTokens helper removed from user list to hide Token actions here. You can still revoke
// tokens from the Tokens -> Active Sessions page.
// --- Styles for template preview boxes (injected via JS for simplicity) ---
try {
    var styleTag = document.createElement('style');
    styleTag.innerHTML = `
    .template-preview-box { border:1px dashed #bfc9ca; background:#f8fbfc; padding:10px 12px; border-radius:6px; margin-top:6px; font-size:14px; color:#2c3e50; }
    .template-preview-box .muted { color:#7f8c8d; font-size:12px; }
    .template-preview-box a { color:#2980b9; text-decoration:none; }
    .template-preview-box b { color:#2c3e50; }
    `;
    document.head && document.head.appendChild(styleTag);
} catch(e) {}

// Inject server-side sample time for preview (so {{time}} formatting matches what will be sent)
<?php
    $tf = get_app_scan_setting($mysqli, $current_admin_id, 'telegram_time_format', 'Y-m-d H:i:s');
    // Safe fallback
    $sample_time = date($tf);
    // Expose to JS
    echo "window.telegram_sample_time = '" . addslashes($sample_time) . "';\n";
?>

// --- Live preview for Telegram templates ---
// Server-provided sample time (formatted using admin setting). Falls back to client time if not available.
var telegram_sample_time = (typeof window !== 'undefined' && window.telegram_sample_time) ? window.telegram_sample_time : null;
// If the admin changes the preset or custom field, update the sample time used by the preview immediately
document.addEventListener('DOMContentLoaded', function(){
    try {
        var tfSelect = document.querySelector('select[name="telegram_time_format_preset"]');
        var tfCustom = document.getElementById('telegram_time_format_custom');
        if (tfSelect) {
            // Initialize: if preset is selected, propagate to custom field
            var initialOpt = tfSelect.options[tfSelect.selectedIndex];
            if (initialOpt && initialOpt.value !== '__custom__') {
                if (tfCustom) tfCustom.value = initialOpt.value;
                if (initialOpt.dataset && initialOpt.dataset.sample) {
                    telegram_sample_time = initialOpt.dataset.sample;
                }
            }
            tfSelect.addEventListener('change', function(){
                var opt = this.options[this.selectedIndex];
                if (opt && opt.value !== '__custom__') {
                    if (tfCustom) tfCustom.value = opt.value; // mirror preset to actual setting field
                    telegram_sample_time = (opt.dataset && opt.dataset.sample) ? opt.dataset.sample : null;
                } else {
                    // Custom mode: do not override the custom text, preview may not match exactly until saved
                    telegram_sample_time = null;
                }
                // Refresh any open previews
                try { updateTemplatePreview('tpl_attendance','attendance','#tpl_attendance_preview'); } catch(e){}
                try { updateTemplatePreview('tpl_request','request','#tpl_request_preview'); } catch(e){}
            });
        }
        if (tfCustom) {
            tfCustom.addEventListener('input', function(){
                // For quick feedback, show typed string with current date/time tokens replaced minimally
                // This is a lightweight approximation for preview only.
                try {
                    var now = new Date();
                    var pad = n => (n<10?('0'+n):n);
                    var txt = this.value || '';
                    txt = txt.replace(/Y/g, now.getFullYear())
                             .replace(/m/g, pad(now.getMonth()+1))
                             .replace(/d/g, pad(now.getDate()))
                             .replace(/H/g, pad(now.getHours()))
                             .replace(/i/g, pad(now.getMinutes()))
                             .replace(/s/g, pad(now.getSeconds()))
                             .replace(/h/g, (function(){var h=now.getHours()%12||12;return pad(h);})())
                             .replace(/g/g, (now.getHours()%12||12))
                             .replace(/A/g, (now.getHours()<12?'AM':'PM'));
                    telegram_sample_time = txt;
                    updateTemplatePreview('tpl_attendance','attendance','#tpl_attendance_preview');
                    updateTemplatePreview('tpl_request','request','#tpl_request_preview');
                } catch(e){}
            });
        }
    } catch(e) {}
});
function getSampleData(type) {
    const now = new Date();
    const pad = n => (n<10?('0'+n):n);
    const clientTimeText = pad(now.getHours())+":"+pad(now.getMinutes())+" "+pad(now.getDate())+"-"+pad(now.getMonth()+1)+"-"+now.getFullYear();
    const timeText = telegram_sample_time || clientTimeText;
    if (type === 'attendance') {
        return {
            name: 'សុភក្រ្ខ ណារ៉ាត',
            employee_id: 'EMP001',
            action: 'Check-In',
            status: 'Good',
            status_icon: '✅',
            time: timeText,
            location_name: 'Head Office',
            distance_m: '12',
            // Raw reason only; line-hiding will remove label line if empty
            late_reason: 'ការរថយន្តជាប់ចរាចរណ៍',
            // Convenience: labeled section that hides itself if empty
            late_reason_section: '<b>មូលហេតុ:</b> ការរថយន្តជាប់ចរាចរណ៍',
            map_url: '<a href="https://maps.google.com/?q=11.556,104.928" target="_blank">មើលទីតាំង</a>',
            // Sample custom fields (so preview shows {{field_department}} / {{field_position}})
            field_department: 'Human Resources',
            field_position: 'Manager'
        };
    }
    return {
        request_type: 'Leave',
        name: 'សុភក្រ្ខ ណារ៉ាត',
        employee_id: 'EMP001',
        summary: 'សុំឈប់ថ្ងៃទី 10-11-2025 ព្រោះមានព្រឹត្តិការណ៍គ្រួសារ។',
        time: timeText
    };
}

function renderTemplate(raw, type) {
    const data = getSampleData(type);
    if (!raw) raw = '';
    // Replace placeholders like {{name}}
    // We'll process line-by-line so that if a line contains placeholders and ALL placeholders on that
    // line are empty/missing, we drop the whole line (removes label-only lines when values are missing).
    const origLines = raw.split(/\r?\n/);
    const outLines = [];

    origLines.forEach(function(line){
        const phMatches = Array.from(line.matchAll(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g));
        if (phMatches.length === 0) {
            // No placeholder on this line: replace any (none) and keep
            outLines.push(line);
            return;
        }
        // If there are placeholders on this line, check if any resolve to non-empty value
        let anyNonEmpty = false;
        let replacedLine = line.replace(/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/g, function(_, key){
            const val = (key in data) ? data[key] : '';
            if (val !== null && String(val).trim() !== '') anyNonEmpty = true;
            return val;
        });
        if (anyNonEmpty) {
            outLines.push(replacedLine);
        } else {
            // all placeholders empty -> drop entire line (removes label)
        }
    });

    // Convert remaining newlines to <br>
    const html = outLines.join('\n').replace(/\r?\n/g, '<br>');
    return html;
}

function updateTemplatePreview(textareaId, type, targetSelector) {
    const ta = document.getElementById(textareaId);
    const target = document.querySelector(targetSelector);
    if (!ta || !target) return;
    target.innerHTML = '<div class="muted">Preview</div>' + renderTemplate(ta.value, type);
}

function bindTemplatePreview() {
    const attTa = document.getElementById('tpl_attendance');
    const reqTa = document.getElementById('tpl_request');
    if (attTa) {
        attTa.addEventListener('input', function(){ updateTemplatePreview('tpl_attendance','attendance','#tpl_attendance_preview'); });
        updateTemplatePreview('tpl_attendance','attendance','#tpl_attendance_preview');
    }
    if (reqTa) {
        reqTa.addEventListener('input', function(){ updateTemplatePreview('tpl_request','request','#tpl_request_preview'); });
        updateTemplatePreview('tpl_request','request','#tpl_request_preview');
    }
    document.querySelectorAll('.toggle-template-preview').forEach(function(cb){
        cb.addEventListener('change', function(){
            const sel = this.getAttribute('data-target');
            const box = document.querySelector(sel);
            if (!box) return;
            box.style.display = this.checked ? 'block' : 'none';
        });
    });
}

function insertPlaceholder(textareaId) {
    try {
        const ta = document.getElementById(textareaId);
        if (!ta) return;
        const isAttendance = (textareaId === 'tpl_attendance');
    const list = isAttendance ? ['name','employee_id','action','status','status_icon','time','location_name','distance_m','late_reason','late_reason_section','map_url'] : ['request_type','name','employee_id','summary','time'];
        const choice = prompt('សូមបញ្ចូល Placeholder ឬជ្រើសពីបញ្ជី:\n' + list.map(k=>`{{${k}}}`).join('  '), list[0]);
        if (!choice) return;
        const text = choice.startsWith('{{') ? choice : ('{{'+choice+'}}');
        const start = ta.selectionStart, end = ta.selectionEnd;
        const before = ta.value.substring(0,start);
        const after = ta.value.substring(end);
        ta.value = before + text + after;
        const pos = start + text.length;
        ta.setSelectionRange(pos,pos);
        ta.focus();
        // Refresh preview
        if (isAttendance) updateTemplatePreview('tpl_attendance','attendance','#tpl_attendance_preview');
        else updateTemplatePreview('tpl_request','request','#tpl_request_preview');
    } catch(e) {}
}

// Bind after DOM parsed
document.addEventListener('DOMContentLoaded', bindTemplatePreview);

// Initialize theme and sidebar preferences early
(function() {
    try {
        const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
        const savedTheme = localStorage.getItem('theme') || (prefersDark ? 'dark' : 'light');
        document.documentElement.setAttribute('data-theme', savedTheme);
        const savedSidebar = localStorage.getItem('sidebarCollapsed');
        if (savedSidebar === '1') document.body.classList.add('sidebar-collapsed');
    } catch (e) {}
})();
// (Removed) Auto-refresh (Users list and groups) — polling disabled per request

function showQrModal(qrUrl, filename) {
	const modal = document.getElementById('qrModal');
	const qrImage = document.getElementById('qr-image-display');
	const downloadLink = document.getElementById('download-link');
	const locationName = filename.replace('QR_', '').replace('_ID', ' ID:').replace('.png', '');
	qrImage.src = qrUrl;
	downloadLink.href = qrUrl;
	downloadLink.download = filename;
	document.getElementById('qr-modal-title').textContent = `QR Code: ${locationName}`;
	modal.style.display = 'block';
}

function editUserModal(userId) {
    const modal = $('#editUserModal');
    const container = $('#editUserFormContainer');
    container.html('<p style="text-align: center;"><i class="fa-solid fa-spinner fa-spin"></i> កំពុងទាញយក</p>');
    modal.show();

    $.ajax({
        type: 'POST',
        url: 'admin_attendance.php',
        data: {
            ajax_action: 'get_user_details',
            user_id: userId
        },
        dataType: 'json',
        success: function(response) {
            if (response.status === 'success') {
                let formHtml = '<form id="editUserForm" class="ajax-form" enctype="multipart/form-data">';
                formHtml += '<input type="hidden" name="ajax_action" value="update_user_info">';
                formHtml += `<input type="hidden" name="edit_id" id="edit_id" value="${response.user_data.employee_id}">`;

                // Standard fields
                formHtml += '<div class="form-group"><label><i class="fa-solid fa-id-card-clip"></i> ID បុគ្គលិក:</label>';
                formHtml += `<input type="text" name="new_id" id="edit_new_id" class="form-control" value="${response.user_data.employee_id}" required></div>`;
                formHtml += '<div class="form-group"><label><i class="fa-solid fa-user"></i> ឈ្មោះ:</label>';
                formHtml += `<input type="text" name="edit_name" id="edit_name" class="form-control" value="${response.user_data.name}" required></div>`;

                // Avatar upload
                const existingAvatar = response.user_data.custom_data && response.user_data.custom_data.avatar ? response.user_data.custom_data.avatar : '';
                formHtml += '<div class="form-group"><label><i class="fa-solid fa-image"></i> រូបប្រវត្តិ (Avatar):</label>';
                if (existingAvatar) {
                    // Add cache-busting param so the preview refreshes after upload
                    const bust = Date.now();
                    const previewSrc = existingAvatar + (existingAvatar.includes('?') ? '&' : '?') + 'v=' + bust;
                    formHtml += `<div style="margin-bottom:8px;"><img src="${previewSrc}" alt="avatar" style="max-width:80px; max-height:80px; border-radius:6px; border:1px solid #ddd;"></div>`;
                }
                formHtml += '<input type="file" name="avatar_file" accept="image/*" class="form-control"></div>';

                // Group select (if groups exist)
                if (response.groups && response.groups.length > 0) {
                    const existingGroupId = (response.user_data.custom_data && response.user_data.custom_data.group_id) ? parseInt(response.user_data.custom_data.group_id) : 0;
                    formHtml += '<div class="form-group"><label><i class="fa-solid fa-layer-group"></i> ក្រុមជំនាញ (Skill Group):</label>';
                    formHtml += '<select name="edit_group_id" class="form-control">';
                    formHtml += '<option value="">— គ្មាន —</option>';
                    response.groups.forEach(g => {
                        const sel = (existingGroupId === parseInt(g.id)) ? 'selected' : '';
                        formHtml += `<option value="${g.id}" ${sel}>${g.group_name}</option>`;
                    });
                    formHtml += '</select></div>';
                }

                // Dynamic custom fields
                response.form_fields.forEach(field => {
                    const value = response.user_data.custom_data[field.field_key] || '';
                    const required_attr = field.is_required ? 'required' : '';
                    formHtml += `<div class="form-group">`;
                    formHtml += `<label>${field.field_label}:</label>`;
                    formHtml += `<input type="${field.field_type}" name="custom[${field.field_key}]" class="form-control" value="${value}" ${required_attr}>`;
                    formHtml += `</div>`;
                });

                formHtml += '<button type="submit" class="btn btn-success" style="width: 100%; margin-top: 15px;"><i class="fa-solid fa-save"></i> រក្សាទុកការកែសម្រួល</button>';
                formHtml += '</form>';
                container.html(formHtml);
            } else {
                container.html(`<p style="color: red;">Error: ${response.message}</p>`);
            }
        },
        error: function() {
            container.html('<p style="color: red;">Error communicating with server.</p>');
        }
    });
}

function applyGroupFilter(gid){
    const url = new URL(window.location.href);
    if (gid) { url.searchParams.set('group_id', gid); } else { url.searchParams.delete('group_id'); }
    window.location.href = url.toString();
}


function editLocationModal(id, name, lat, lon, radius) {
	document.getElementById('edit_loc_id').value = id;
	document.getElementById('edit_loc_name').value = name;
	document.getElementById('edit_latitude').value = lat;
	document.getElementById('edit_longitude').value = lon;
	document.getElementById('edit_radius_meters').value = radius;
	document.getElementById('editLocationModal').style.display = 'block';
}

function showRequestDetailsModal(requestData) {
    const modal = document.getElementById('requestDetailModal');
    document.getElementById('modal_req_id').value = requestData.id;
    document.getElementById('modal_req_id_display').textContent = requestData.id;
    document.getElementById('modal_req_name').textContent = requestData.name;
    document.getElementById('modal_req_employee_id').textContent = requestData.employee_id;
    document.getElementById('modal_req_type').textContent = requestData.request_type.replace(/-/g, ' ');
    const statusClass = 'status-' + requestData.request_status.toLowerCase();
    document.getElementById('modal_req_status').innerHTML = `<span class="status-badge ${statusClass}">${requestData.request_status}</span>`;
    const submittedDate = new Date(requestData.submitted_at).toLocaleString('en-GB');
    const eventDate = requestData.event_date ? new Date(requestData.event_date).toLocaleDateString('en-GB') : 'N/A';
    document.getElementById('modal_req_submitted').textContent = submittedDate;
    document.getElementById('modal_req_event_date').textContent = eventDate;
    document.getElementById('modal_req_reason').textContent = requestData.reason_detail || '(No reason provided)';

    // NEW: Handle and display custom data
    const customContainer = document.getElementById('modal_req_custom_data_container');
    customContainer.innerHTML = ''; // Clear previous data

    if (requestData.custom_data) {
        try {
            const customData = JSON.parse(requestData.custom_data);
            if(Object.keys(customData).length > 0) {
                let customHtml = '<h4 style="margin-top: 20px; margin-bottom: 5px; color: #34495e;"><i class="fa-solid fa-paperclip"></i> ព័ត៌មានបន្ថែម</h4>';
                customHtml += '<div class="detail-grid">';
                for (const key in customData) {
                    let label = key.replace(/_/g, ' ').replace('custom ', '');
                    label = label.charAt(0).toUpperCase() + label.slice(1);

                    customHtml += `<div>${label}</div><div>${customData[key] || 'N/A'}</div>`;
                }
                customHtml += '</div>';
                customContainer.innerHTML = customHtml;
            }
        } catch (e) {
            console.error("Could not parse custom_data JSON", e);
        }
    }

    const footer = document.getElementById('modal_req_footer');
    if (requestData.request_status === 'Pending') {
        footer.style.display = 'flex';
        footer.style.justifyContent = 'flex-end';
    } else {
        footer.style.display = 'none';
    }
    modal.style.display = 'block';
}


function handleRequestAction(newStatus) {
    const requestId = document.getElementById('modal_req_id').value;
    const actionText = newStatus === 'Approved' ? 'យល់ព្រម' : 'បដិសេធ';

    if (confirm(`តើអ្នកពិតជាចង់ "${actionText}" សំណើរនេះមែនទេ?`)) {
        $.ajax({
            type: 'POST', url: 'admin_attendance.php',
            data: { ajax_action: 'update_request_status', request_id: requestId, new_status: newStatus },
            dataType: 'json',
            success: function(response) {
                if (response.status === 'success') {
                    showAjaxMessage('success', response.message);
                    smartPageRefresh(1500);
                } else {
                    showAjaxMessage('error', response.message);
                }
            },
            error: function(xhr) { showAjaxMessage('error', 'Error communicating with the server: ' + xhr.responseText); }
        });
    }
}

function toggleExpiryField(accessMode) {
    document.getElementById('expiryDateGroup').style.display = (accessMode === 'Paid') ? 'block' : 'none';
}

// Generic export function for any HTML table to Excel
async function exportTableToExcel(tableId, filenamePref) {
    if (!(window.ExcelJS && window.saveAs)) {
        alert('Excel export libraries not loaded.');
        return;
    }

    const table = document.getElementById(tableId);
    if (!table) return;

    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Sheet1');

    const rows = [];
    const theadRows = Array.from(table.querySelectorAll('thead tr'));
    const tbodyRows = Array.from(table.querySelectorAll('tbody tr'));
    const tfootRows = Array.from(table.querySelectorAll('tfoot tr'));

    // We'll manually build the sheet to handle the headers correctly
    let currentRowIdx = 1;

    // Title handling (Optional, but good for reports)
    const titleVal = table.previousElementSibling && table.previousElementSibling.tagName === 'H2' ? table.previousElementSibling.textContent : 'Report';
    sheet.addRow([titleVal.trim()]);
    sheet.getRow(1).font = { name: 'Khmer OS Muol Light', bold: true, size: 14 };
    currentRowIdx++;
    sheet.addRow([]); // spacer
    currentRowIdx++;

    const startTableDataRow = currentRowIdx;

    // Process thead
    theadRows.forEach(tr => {
        const rowData = [];
        Array.from(tr.children).forEach(cell => {
            rowData.push((cell.textContent || '').trim());
            // handle colspan/rowspan if needed? for now just push text
        });
        sheet.addRow(rowData);
        const sheetRow = sheet.getRow(currentRowIdx);
        sheetRow.font = { name: 'Kh Siemreap', bold: true, size: 11 };
        sheetRow.alignment = { vertical: 'middle', horizontal: 'center' };
        // Basic styling
        sheetRow.eachCell(cell => {
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE9ECEF' } };
            cell.border = { top: {style:'thin'}, left: {style:'thin'}, bottom: {style:'thin'}, right: {style:'thin'} };
        });
        currentRowIdx++;
    });

    // Process tbody
    tbodyRows.forEach(tr => {
        const rowData = [];
        Array.from(tr.children).forEach(cell => {
            rowData.push((cell.textContent || '').trim());
        });
        sheet.addRow(rowData);
        const sheetRow = sheet.getRow(currentRowIdx);
        sheetRow.font = { name: 'Kh Siemreap', size: 10 };
        sheetRow.eachCell(cell => {
            cell.border = { top: {style:'thin'}, left: {style:'thin'}, bottom: {style:'thin'}, right: {style:'thin'} };
        });
        currentRowIdx++;
    });

    // Process tfoot
    tfootRows.forEach(tr => {
        const rowData = [];
        Array.from(tr.children).forEach(cell => {
            rowData.push((cell.textContent || '').trim());
        });
        sheet.addRow(rowData);
        const sheetRow = sheet.getRow(currentRowIdx);
        sheetRow.font = { name: 'Kh Siemreap', bold: true, size: 10 };
        sheetRow.eachCell(cell => {
            cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFF3CD' } };
            cell.border = { top: {style:'thin'}, left: {style:'thin'}, bottom: {style:'thin'}, right: {style:'thin'} };
        });
        currentRowIdx++;
    });

    // Auto-width
    sheet.columns.forEach(column => {
        let maxLen = 0;
        column.values.forEach(v => {
            if (v) maxLen = Math.max(maxLen, v.toString().length);
        });
        column.width = Math.min(50, Math.max(10, maxLen + 2));
    });

    const buffer = await workbook.xlsx.writeBuffer();
    const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    saveAs(blob, (filenamePref || 'Report') + '.xlsx');
}

// Export reports table to Excel (.xlsx via ExcelJS)
async function exportReportsToXlsx() {
    // Ensure ExcelJS is loaded
    if (!(window.ExcelJS && window.saveAs)) {
        alert('Excel export libraries not loaded.');
        return;
    }

    // Prefer the dedicated export table to guarantee no Actions column
    let exportTableEl = document.getElementById('reportsTableExport');

// Fallback: dynamically build headers/rows using stable data-col keys
let headers = [];
let rows = [];

// Build list of visible data-col keys from the main table (excluding selection/actions)
const mainTable = document.getElementById('reportsTable');
const visibleKeys = mainTable ? Array.from(mainTable.querySelectorAll('thead th[data-col]')).filter(th => th.style.display !== 'none').map(th => th.getAttribute('data-col')) : [];
const excludeKeys = ['select', 'operations'];
const keysToInclude = visibleKeys.filter(k => k && excludeKeys.indexOf(k) === -1);

if (exportTableEl) {
    // Export table uses matching data-col attributes — pick only those keys that are visible
    const exportThs = Array.from(exportTableEl.querySelectorAll('thead th[data-col]'));
    const filteredExportThs = exportThs.filter(th => keysToInclude.includes(th.getAttribute('data-col')));
    headers = filteredExportThs.map(th => (th.textContent || '').trim());
    rows = Array.from(exportTableEl.querySelectorAll('tbody tr')).map(tr => {
        const tds = Array.from(tr.children);
        return filteredExportThs.map((th, idx) => {
            const key = th.getAttribute('data-col');
            const td = tr.querySelector('.col-' + key);
            if (td) return (td.textContent || '').trim();
            // fallback: try cell by same index in export row
            return (tds[idx] ? (tds[idx].textContent || '') : '').trim();
        });
    });
    } else {
        const src = mainTable;
        if (src) {
            // Cache header THs once for index fallbacks
            const allThs = Array.from(src.querySelectorAll('thead th'));
            // Build headers from the stable keys list (keysToInclude)
            headers = keysToInclude.map(k => {
                const th = src.querySelector('thead th[data-col="' + k + '"]');
                return th ? (th.textContent || '').replace(/\s+/g,' ').trim() : k;
            });

            // Build rows using .col-<key> cells when available, otherwise fallback to column index
            rows = Array.from(src.querySelectorAll('tbody tr')).map(tr => {
                return keysToInclude.map(k => {
                    const td = tr.querySelector('.col-' + k);
                    if (td) return (td.textContent || '').trim();
                    // fallback: find column index by matching header's data-col
                    const idx = allThs.findIndex(t => t.getAttribute('data-col') === k);
                    const tds = Array.from(tr.children);
                    return (tds[idx] ? (tds[idx].textContent || '') : '').trim();
                });
            });
        } else {
            // No source table found — ensure arrays are empty
            headers = [];
            rows = [];
        }
    }

    if (headers.length === 0) { alert('No data to export'); return; }

    // Normalize headers (remove empties, ensure uniqueness)
    headers = headers.map(h => h || '');
    const nameCount = {};
    headers = headers.map(h => {
        const base = h.trim() || 'Column';
        if (!nameCount[base]) { nameCount[base] = 1; return base; }
        const next = base + ' (' + (++nameCount[base]) + ')';
        return next;
    });

    // Normalize rows to have exact same length as headers
    rows = rows.map(r => Array.isArray(r) ? r : []).map(r => {
        const arr = r.map(v => (v ?? '').toString());
        if (arr.length > headers.length) { return arr.slice(0, headers.length); }
        if (arr.length < headers.length) {
            const pad = new Array(headers.length - arr.length).fill('');
            return arr.concat(pad);
        }
        return arr;
    });

    // Workbook and sheet
    const workbook = new ExcelJS.Workbook();
    const sheet = workbook.addWorksheet('Attendance');

    // Title and filter rows
    const title = 'របាយការណ៍វត្តមានបុគ្គលិក';
    const dateSel = document.getElementById('filter_date');
    const statusSel = document.getElementById('filter_status');
    const dateVal = dateSel ? dateSel.value : new Date().toISOString().slice(0,10);
    const statusVal = statusSel ? statusSel.value : 'All';

    sheet.addRow([title]);
    sheet.mergeCells(1,1,1,headers.length);
    // Title: Khmer OS Muol Light
    sheet.getRow(1).font = { name: 'Khmer OS Muol Light', bold: true, size: 16 };
    sheet.addRow([`កាលបរិច្ឆេទ: ${dateVal}    |    ស្ថានភាព: ${statusVal}`]);
    // Filter info row: Kh Siemreap
    sheet.getRow(2).font = { name: 'Kh Siemreap', size: 12 };
    sheet.mergeCells(2,1,2,headers.length);
    sheet.addRow([]); // blank

    // Add as a styled table
    const startRow = sheet.lastRow.number + 1; // should be 4
    const xTable = sheet.addTable({
        name: 'AttendanceTable',
        ref: `A${startRow}`,
        headerRow: true,
        totalsRow: false,
        style: { theme: 'TableStyleMedium9', showRowStripes: true },
        columns: headers.map(h => ({ name: h, filterButton: true })),
        rows: rows
    });

    // Apply fonts inside the table region
    // Header row of the table
    const headerRowIdx = startRow;
    for (let c = 1; c <= headers.length; c++) {
        const cell = sheet.getCell(headerRowIdx, c);
        cell.font = { name: 'Kh Siemreap', bold: true, size: 12 };
    }
    // Body rows of the table
    for (let r = 0; r < rows.length; r++) {
        const excelRowIdx = startRow + 1 + r;
        for (let c = 1; c <= headers.length; c++) {
            const cell = sheet.getCell(excelRowIdx, c);
            cell.font = { name: 'Kh Siemreap', size: 12 };
        }
    }

    // Column widths (simple heuristic)
    const colWidths = headers.map((h, idx) => {
        let maxLen = h.length;
        rows.forEach(r => { maxLen = Math.max(maxLen, (r[idx] ? r[idx].length : 0)); });
        return Math.min(40, Math.max(12, Math.ceil(maxLen * 1.1)));
    });
    sheet.columns = colWidths.map(w => ({ width: w }));

    // Freeze top rows (title + filter + blank + header)
    sheet.views = [{ state: 'frozen', ySplit: 4 }];

    // Filename
    const filename = `Attendance_${dateVal}_${statusVal}.xlsx`;

    const buffer = await workbook.xlsx.writeBuffer();
    const blob = new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
    saveAs(blob, filename);
}

// Bind export button
(function(){
    const btn = document.getElementById('exportExcelBtn');
    if (!btn) return;
    btn.addEventListener('click', function(){
        exportReportsToXlsx().catch(function(err){
            console.error('Export error', err);
            alert('Export failed: ' + (err && err.message ? err.message : 'Unknown error'));
        });
    });
})();

window.onclick = function(event) {
	const modals = document.getElementsByClassName('modal');
    for (let i = 0; i < modals.length; i++) {
        if (event.target == modals[i]) {
            modals[i].style.display = 'none';
        }
    }
}

// Helper: Format late duration given integer minutes
function format_late_minutes(mins) {
    if (mins === null || mins === '') return '';
    var m = parseInt(mins, 10);
    if (isNaN(m) || m <= 0) return '';
    if (m >= 60) {
        var h = Math.floor(m / 60);
        var r = m % 60;
        if (r === 0) {
            return h + ' ម៉ោង';
        }
        return h + ' ម៉ោង ' + r + ' នាទី';
    }
    return m + ' នាទី';
}

function addTimeRule(type, start = '08:00:00', end = '09:00:00', status = 'Good') {
	const container = document.getElementById(type + 'RulesContainer');
	const html = `
		<div class="time-rule-row" data-type="${type}">
			<label><i class="fa-solid fa-play"></i> ចាប់ពី</label>
			<input type="time" class="form-control rule-start" value="${start}" step="1" required>
			<label><i class="fa-solid fa-stop"></i> ដល់</label>
			<input type="time" class="form-control rule-end" value="${end}" step="1" required>
			<label><i class="fa-solid fa-circle-info"></i> ស្ថានភាព</label>
			<select class="form-control rule-status">
				<option value="Good" ${status === 'Good' ? 'selected' : ''}>✅ Good</option>
				<option value="Late" ${status === 'Late' ? 'selected' : ''}>⚠️ Late</option>
				<option value="Absent" ${status === 'Absent' ? 'selected' : ''}>❌ Absent</option>
			</select>
			<button type="button" class="btn btn-danger remove-rule" onclick="this.parentNode.remove()"><i class="fa-solid fa-trash"></i></button>
		</div>`;
	container.insertAdjacentHTML('beforeend', html);
}

function prepareAndSubmitRules() {
	const allRules = [];
	const ruleRows = document.querySelectorAll('#timeRulesForm .time-rule-row');
	let hasError = false;
	ruleRows.forEach(row => {
		const type = row.getAttribute('data-type'), startInput = row.querySelector('.rule-start').value,
		      endInput = row.querySelector('.rule-end').value, statusInput = row.querySelector('.rule-status').value;
		if (startInput === "" || endInput === "") {
			 showAjaxMessage('error', "សូមបំពេញម៉ោងចាប់ផ្តើម និងបញ្ចប់ឱ្យបានពេញលេញ!");
			 hasError = true; return;
		}
		if (type === 'checkin' && new Date(`2000/01/01 ${startInput}`) >= new Date(`2000/01/01 ${endInput}`)) {
			 showAjaxMessage('error', `ម៉ោងចាប់ពី (${startInput}) ត្រូវតែតូចជាងម៉ោងដល់ (${endInput}) សម្រាប់ Check-in!`);
			 hasError = true; return;
		}
		allRules.push({ type: type, start: startInput, end: endInput, status: statusInput });
	});
	if (hasError) return false;
	document.getElementById('rulesJsonInput').value = JSON.stringify(allRules);
	return true;
}

function showAjaxMessage(status, message) {
	const container = $('#ajax-message-container'), alertClass = status === 'success' ? 'alert-success' : 'alert-danger',
	      iconClass = status === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation';
	container.empty().html(`<div class="alert ${alertClass}"><i class="fa-solid ${iconClass}"></i> ${message}</div>`).show();
	$('html, body').animate({ scrollTop: 0 }, 'fast');
	if (status === 'success') { setTimeout(() => container.fadeOut(500), 5000); }
}

/**
 * Smart page refresh — reloads only the .main-content area via fetch
 * instead of a full window.location.reload(). Falls back to full reload
 * if partial fetch fails or the page structure has changed significantly.
 */
let _smartRefreshInProgress = false;
function smartPageRefresh(delay = 0) {
    if (delay > 0) {
        setTimeout(() => smartPageRefresh(0), delay);
        return;
    }
    if (_smartRefreshInProgress) return;
    _smartRefreshInProgress = true;

    const url = window.location.href;
    fetch(url, { credentials: 'same-origin', headers: { 'X-Requested-With': 'smartRefresh' } })
        .then(res => {
            if (!res.ok) throw new Error('fetch failed: ' + res.status);
            return res.text();
        })
        .then(html => {
            const parser = new DOMParser();
            const doc = parser.parseFromString(html, 'text/html');
            // Refresh main-content area only
            const newMain = doc.querySelector('.main-content');
            const curMain = document.querySelector('.main-content');
            if (newMain && curMain) {
                curMain.innerHTML = newMain.innerHTML;
                // Re-init any inline scripts inside the refreshed content
                curMain.querySelectorAll('script').forEach(oldScript => {
                    const s = document.createElement('script');
                    if (oldScript.src) s.src = oldScript.src;
                    else s.textContent = oldScript.textContent;
                    oldScript.parentNode.replaceChild(s, oldScript);
                });
                // Update pending badge if present
                const newBadge = doc.querySelector('#pendingRequestsBadge');
                const curBadge = document.querySelector('#pendingRequestsBadge');
                if (newBadge && curBadge) curBadge.outerHTML = newBadge.outerHTML;
                _smartRefreshInProgress = false;
            } else {
                // Structure mismatch — fall back to full reload
                window.location.reload();
            }
        })
        .catch(() => {
            _smartRefreshInProgress = false;
            window.location.reload();
        });
}


function submitAjaxForm(formElement, initialResponse = null) {
	const $form = $(formElement), action = $form.find('[name="ajax_action"]').val();
	if (initialResponse) {
        if (initialResponse.status === 'success') {
            showAjaxMessage('success', initialResponse.message);
            smartPageRefresh(1500);
        } else {
            showAjaxMessage('error', initialResponse.message);
        }
        return;
    }
	const $submitBtn = $form.find('button[type="submit"]'), originalText = $submitBtn.html();
	if (formElement.id === 'timeRulesForm' && !prepareAndSubmitRules()) { return; }
    if (formElement.id === 'updateSubscriptionForm') {
        const mode = $form.find('#access_mode').val(), expiry = $form.find('#expiry_datetime').val();
        if (mode === 'Paid' && expiry === '') {
            showAjaxMessage('error', "របៀប Paid តម្រូវឱ្យមានថ្ងៃ និងម៉ោងផុតកំណត់!");
            return;
        }
    }
	$submitBtn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងដំណើរការ...');
	$('#ajax-message-container').hide().empty();
	$.ajax({
		type: 'POST', url: 'admin_attendance.php', data: $form.serialize(), dataType: 'json',
		success: function(response) {
			if (response.status === 'success') {
				showAjaxMessage('success', response.message);
				$form.closest('.modal').hide();
                setTimeout(() => {
                    if(response.refresh_url) { window.location.href = response.refresh_url; }
                    else { smartPageRefresh(0); }
                }, 1500);
			} else { showAjaxMessage('error', response.message); }
		},
		error: function(xhr, status, error) { showAjaxMessage('error', `មានកំហុសក្នុងការតភ្ជាប់ Server៖ ${xhr.responseText.substring(0, 100)}...`); },
		complete: function() { $submitBtn.prop('disabled', false).html(originalText); }
	});
}

function submitAjaxFormWithFile(formElement) {
    const $form = $(formElement), $submitBtn = $form.find('button[type="submit"]'), originalText = $submitBtn.html();
    $submitBtn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងដំណើរការ...');
	$('#ajax-message-container').hide().empty();
    const formData = new FormData(formElement);
    $.ajax({
		type: 'POST', url: 'admin_attendance.php', data: formData,
        processData: false, contentType: false, dataType: 'json',
		success: function(response) {
			if (response.status === 'success') {
				showAjaxMessage('success', response.message);
                smartPageRefresh(1500);
			} else { showAjaxMessage('error', response.message); }
		},
        error: function(xhr) { showAjaxMessage('error', `មានកំហុស: ${xhr.responseText.substring(0, 100)}...`); },
		complete: function() { $submitBtn.prop('disabled', false).html(originalText); }
	});
}

$(document).ready(function() {
    // Initialize theme icon
    (function initThemeIcon(){
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        const $icon = $('#toggleTheme i');
        if ($icon.length) {
            if (current === 'dark') { $icon.removeClass('fa-moon').addClass('fa-sun'); }
            else { $icon.removeClass('fa-sun').addClass('fa-moon'); }
        }
    })();

    // Apply persisted sidebar collapsed state (desktop)
    try {
        if (localStorage.getItem('sidebarCollapsed') === '1' && !window.matchMedia('(max-width: 980px)').matches) {
            $('body').addClass('sidebar-collapsed');
        }
    } catch(e) { /* ignore storage errors */ }

    // Theme toggle handler
    $('#toggleTheme').on('click', function() {
        const current = document.documentElement.getAttribute('data-theme') || 'light';
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        try { localStorage.setItem('theme', next); } catch(e) {}
        const $icon = $(this).find('i');
        $icon.toggleClass('fa-moon', next === 'light');
        $icon.toggleClass('fa-sun', next === 'dark');
    });

    // Sidebar toggle (desktop collapse or mobile drawer)
    $('#toggleSidebar').on('click', function() {
        if (window.matchMedia('(max-width: 980px)').matches) {
            const $sidebar = $('.sidebar');
            const $overlay = $('#sidebarOverlay');
            const willOpen = !$sidebar.hasClass('open');
            $sidebar.toggleClass('open', willOpen);
            $overlay.toggleClass('show', willOpen);
            $('body').toggleClass('no-scroll', willOpen);
        } else {
            $('body').toggleClass('sidebar-collapsed');
            try { localStorage.setItem('sidebarCollapsed', $('body').hasClass('sidebar-collapsed') ? '1' : '0'); } catch(e) {}
        }
    });

    // Close mobile drawer when clicking overlay or any sidebar link
    $('#sidebarOverlay').on('click', function() {
        $('.sidebar').removeClass('open');
        $(this).removeClass('show');
        $('body').removeClass('no-scroll');
    });
    $('.sidebar').on('click', 'a', function(e) {
        // Do not close when tapping submenu toggle (expand/collapse only)
        if ($(this).hasClass('submenu-toggle')) return;
        if (window.matchMedia('(max-width: 980px)').matches) {
            $('.sidebar').removeClass('open');
            $('#sidebarOverlay').removeClass('show');
            $('body').removeClass('no-scroll');
        }
        // Trigger loader when navigating to new page via sidebar link that changes ?page= or action
        const href = $(this).attr('href');
        if (href && href.indexOf('admin_attendance.php') !== -1) {
            try { showAdminLoader('កំពុងផ្ទុកទំព័រ...'); } catch(e) {}
        }
    });

    // Close on Escape in mobile
    $(document).on('keydown', function(e) {
        if (e.key === 'Escape' && window.matchMedia('(max-width: 980px)').matches) {
            if ($('.sidebar').hasClass('open')) {
                $('.sidebar').removeClass('open');
                $('#sidebarOverlay').removeClass('show');
                $('body').removeClass('no-scroll');
            }
        }
    });

    // Sync state on resize boundaries
    $(window).on('resize', function() {
        const isMobile = window.matchMedia('(max-width: 980px)').matches;
        if (!isMobile) {
            // Ensure overlay is hidden and body scroll restored
            $('#sidebarOverlay').removeClass('show');
            $('body').removeClass('no-scroll');
            // Respect persisted desktop collapsed state (no change here)
        } else {
            // In mobile, remove desktop collapsed class to avoid narrow content
            $('body').removeClass('sidebar-collapsed');
        }
    });
	$(document).on('submit', '.ajax-form', function(e) {
		e.preventDefault();
        if ($(this).attr('enctype') === 'multipart/form-data') {
            submitAjaxFormWithFile(this);
        } else {
            // Need to handle forms inside modals specifically
            if($(this).attr('id') === 'editUserForm') {
                submitAjaxForm(this);
            } else {
                submitAjaxForm(this);
            }
        }
	});

    // Copy time rules from another user: handler for Copy button in edit_rules page
    $(document).on('click', '#copyFromUserBtn', function() {
        const userId = $('#copyFromUserSelect').val();
        if (!userId) { alert('សូមជ្រើសរើសអ្នកប្រើណាមួយដើម្បី Copy ពីវា'); return; }
        const $btn = $(this); const original = $btn.html();
        $btn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងទាញ...');
        $.ajax({
            type: 'POST', url: 'admin_attendance.php', dataType: 'json',
            data: { ajax_action: 'get_time_rules', user_id: userId },
            success: function(res) {
                if (res.status === 'success') {
                    // Clear current rules
                    $('#checkinRulesContainer').empty(); $('#checkoutRulesContainer').empty();
                    const rules = res.rules || [];
                    if (rules.length === 0) { showAjaxMessage('error', 'មិនមានច្បាប់ម៉ោងក្នុងប្រព័ន្ធសម្រាប់ User នេះ'); return; }
                    rules.forEach(function(r) {
                        try { addTimeRule(r.type, r.start_time, r.end_time, r.status); } catch(e) { console.error(e); }
                    });
                    showAjaxMessage('success', 'បានទាញច្បាប់ម៉ោងពីអ្នកប្រើជោគជ័យ — អាចកែប្រែបាន។');
                } else { showAjaxMessage('error', res.message || 'Failed to fetch rules'); }
            },
            error: function(xhr) { showAjaxMessage('error', 'Network/server error fetching rules'); },
            complete: function() { $btn.prop('disabled', false).html(original); }
        });
    });

    // Handle dynamically loaded forms inside modals
    $(document).on('submit', '#editUserForm', function(e) {
        e.preventDefault();
        submitAjaxForm(this);
    });

	$(document).on('click', '.ajax-delete-link', function(e) {
		e.preventDefault();
		const $this = $(this), message = $this.data('confirm') || 'តើអ្នកពិតជាចង់លុបទិន្នន័យនេះមែនទេ?';
		if (confirm(message)) {
			let dataToSend = { ajax_action: $this.data('ajax-action') };
            // Add specific data based on action
            if($this.data('token')) dataToSend.token = $this.data('token');
            if($this.data('assign-id')) dataToSend.assign_id = $this.data('assign-id');
            if($this.data('loc-id')) dataToSend.loc_id = $this.data('loc-id');
            if($this.data('field-id')) dataToSend.field_id = $this.data('field-id');
            if($this.data('user-id')) dataToSend.user_id = $this.data('user-id');

            $.ajax({
				type: 'POST', url: 'admin_attendance.php', data: dataToSend, dataType: 'json',
				success: function(response) {
                    if (response.status === 'success') {
                        showAjaxMessage('success', response.message);
                        smartPageRefresh(1500);
                    } else {
                        showAjaxMessage('error', response.message);
                    }
				},
                error: function(xhr) { showAjaxMessage('error', 'មានកំហុសក្នុងការលុប: ' + (xhr.responseText || '')); }
			});
		}
	});

	if (window.location.search.includes('edit_rules')) {
		const ciContainer = document.getElementById('checkinRulesContainer');
		if (ciContainer && ciContainer.children.length === 0) {
			addTimeRule('checkin', '07:00:00', '08:00:00', 'Good');
			addTimeRule('checkin', '08:00:01', '09:00:00', 'Late');
			addTimeRule('checkout', '17:00:00', '18:00:00', 'Good');
			addTimeRule('checkout', '16:00:00', '16:59:59', 'Late');
		}
	}

	$('.submenu-toggle').on('click', function(event) {
        event.preventDefault();
        const parentItem = $(this).closest('.sidebar-item');
        const wasOpen = parentItem.hasClass('open');

        // Close all other open submenus
        $('.sidebar-item.has-submenu.open').not(parentItem).removeClass('open');

        // Toggle the current one
        if (!wasOpen) {
            parentItem.addClass('open');
        } else {
             parentItem.removeClass('open');
        }
    });

    // Make parent menu active when on a sub-page
    const activeSubmenuLink = $('.submenu a.sub-active');
    if (activeSubmenuLink.length > 0) {
        activeSubmenuLink.closest('.sidebar-item.has-submenu').addClass('active open');
    }

    // Open Late Reason modal
    $(document).on('click', '.edit-late-reason', function() {
        const logId = parseInt($(this).data('log-id'), 10) || 0;
        const current = $(this).data('current-reason') || '';
        $('#late_reason_log_id').val(logId);
        $('#late_reason_text').val(current);
        $('#lateReasonModal').show();
    });

    // Save Late Reason via AJAX
    $('#saveLateReasonBtn').on('click', function() {
        const logId = parseInt($('#late_reason_log_id').val(), 10) || 0;
        const reason = $('#late_reason_text').val();
        if (!logId) { alert('Invalid log id'); return; }
        const $btn = $(this);
        const original = $btn.html();
        $btn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងរក្សាទុក...');
        $.ajax({
            type: 'POST', url: 'admin_attendance.php', dataType: 'json',
            data: { ajax_action: 'update_late_reason', log_id: logId, late_reason: reason },
            success: function(res) {
                if (res.status === 'success') {
                    // Update table cell text for this log row
                    const $rowBtn = $(`.edit-late-reason[data-log-id="${logId}"]`);
                    $rowBtn.data('current-reason', reason);
                    $rowBtn.closest('tr').find('.late-reason-cell').text(reason || 'N/A');
                    $('#lateReasonModal').hide();
                    showAjaxMessage('success', 'បានរក្សាទុកមូលហេតុ (late reason) ដោយជោគជ័យ');
                } else {
                    showAjaxMessage('error', res.message || 'រក្សាទុកបរាជ័យ');
                }
            },
            error: function(xhr) {
                showAjaxMessage('error', 'បញ្ហា Network/Server: ' + (xhr.responseText || ''));
            },
            complete: function(){ $btn.prop('disabled', false).html(original); }
        });
    });

    // Inline edit for noted
    $(document).on('blur', '.noted-cell', function() {
        const $cell = $(this);
        const logId = $cell.data('log-id');
        const noted = $cell.text().trim();
        if (!logId) return;

        // Visual indicator: Saving...
        const originalBg = $cell.css('backgroundColor');
        $cell.css('backgroundColor', '#fef9c3'); // Light yellow indicating pending

        // Save via AJAX
        $.ajax({
            type: 'POST', url: 'admin_attendance.php', dataType: 'json',
            data: { ajax_action: 'update_noted', log_id: logId, noted: noted },
            success: function(res) {
                if (res.status === 'success') {
                    // Update the cell display without full re-render if unnecessary, or careful render
                    let displayHtml = noted;
                    if (noted.match(/^https?:\/\//)) {
                        displayHtml = '<a href="' + noted.replace(/"/g, '&quot;') + '" target="_blank" rel="noopener noreferrer">' + noted.replace(/</g, '&lt;').replace(/>/g, '&gt;') + '</a>';
                    }
                    $cell.html(displayHtml);

                    // Success indicator: Flash green then fade back
                    $cell.css('backgroundColor', '#dcfce7'); // Light green
                    setTimeout(() => { $cell.css('backgroundColor', originalBg); }, 1000);

                    // Do NOT call showAjaxMessage to prevent scroll jump
                    // showAjaxMessage('success', 'Noted updated successfully.');
                } else {
                    $cell.css('backgroundColor', '#fee2e2'); // Light red
                    showAjaxMessage('error', res.message || 'Update failed'); // Only show global error on failure
                }
            },
            error: function(xhr) {
                $cell.css('backgroundColor', '#fee2e2');
                showAjaxMessage('error', 'Network/Server error: ' + (xhr.responseText || ''));
            }
        });
    });

    // Prevent link clicks in noted-cell and enter edit mode instead
    $(document).on('click', '.noted-cell a', function(e) {
        e.preventDefault();
        const $cell = $(this).closest('.noted-cell');
        $cell.focus();
        // Select all text for easy editing
        const range = document.createRange();
        range.selectNodeContents($cell[0]);
        const sel = window.getSelection();
        sel.removeAllRanges();
        sel.addRange(range);
    });

    // Open Duplicate User modal
    $(document).on('click', '.open-duplicate-user', function() {
        const srcId = $(this).data('src-id') || '';
        const srcName = $(this).data('src-name') || '';
        $('#dup_src_id').val(srcId);
        $('#dup_src_display').val(`${srcName} (${srcId})`);
        $('#dup_new_id').val('');
        $('#dup_new_name').val('');
        $('#duplicateUserModal').show();
    });

    // Submit duplicate form
    $(document).on('submit', '#duplicateUserForm', function(e) {
        e.preventDefault();
        submitAjaxForm(this);
    });

    // Users list: Select all / per-row checkbox
    $(document).on('change', '#selectAllUsers', function() {
        const checked = $(this).is(':checked');
        $('.user-select').prop('checked', checked).trigger('change');
    });
    $(document).on('change', '.user-select', function() {
        const any = $('.user-select:checked').length > 0;
        $('#bulkDeleteBtn').prop('disabled', !any);
        $('#assignSelectedGroupBtn').prop('disabled', !any);
    });

    // Bulk delete selected users
    $('#bulkDeleteBtn').on('click', function() {
        const ids = $('.user-select:checked').map(function(){ return $(this).val(); }).get();
        if (ids.length === 0) return;
        if (!confirm('តើអ្នកពិតជាចង់លុបអ្នកប្រើប្រាស់ដែលបានជ្រើសមែនទេ?')) return;
        const $btn = $(this);
        const prev = $btn.html();
        $btn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងលុប...');
        $.ajax({
            type: 'POST', url: 'admin_attendance.php', dataType: 'json',
            data: { ajax_action: 'bulk_delete_users', employee_ids: ids },
            success: function(res) {
                if (res.status === 'success') {
                    showAjaxMessage('success', res.message);
                    smartPageRefresh(1200);
                } else {
                    showAjaxMessage('error', res.message || 'លុបបរាជ័យ');
                }
            },
            error: function(xhr){ showAjaxMessage('error', 'បញ្ហា Network/Server: ' + (xhr.responseText || '')); },
            complete: function(){ $btn.prop('disabled', false).html(prev); }
        });
    });

    // Bulk assign selected users to group
    $('#assignSelectedGroupForm').on('submit', function() {
        const ids = $('.user-select:checked').map(function(){ return $(this).val(); }).get();
        if (ids.length === 0) { showAjaxMessage('error', 'មិនបានជ្រើសរើសអ្នកប្រើប្រាស់ទេ'); return false; }
        const groupIdRaw = $('#bulk_group_id').val();
        const groupId = groupIdRaw === '' ? '' : groupIdRaw; // blank => remove group
        const $btn = $('#assignSelectedGroupBtn');
        const prevHtml = $btn.html();
        $btn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងកំណត់...');
        $.ajax({
            type: 'POST', url: 'admin_attendance.php', dataType: 'json',
            data: { ajax_action: 'assign_user_group', employee_ids: ids, group_id: groupId },
            success: function(res){
                if (res.status === 'success') {
                    showAjaxMessage('success', res.message || 'បានកំណត់ក្រុម');
                    smartPageRefresh(1000);
                } else {
                    showAjaxMessage('error', res.message || 'បរាជ័យក្នុងការកំណត់ក្រុម');
                }
            },
            error: function(xhr){ showAjaxMessage('error', 'បញ្ហា Network/Server: ' + (xhr.responseText || '')); },
            complete: function(){ $btn.prop('disabled', false).html(prevHtml); }
        });
        return false;
    });

    // ===== Drag & Drop reorder for Skill Groups (Categories page) =====
    (function(){
        const $tbody = $('#groupsTableBody');
        if ($tbody.length === 0) return; // Only on categories page

        let $dragging = null;

        function attachDnD(){
            $tbody.find('tr.draggable-group').each(function(){
                const $row = $(this);
                $row.on('dragstart', function(e){
                    $dragging = $row;
                    e.originalEvent.dataTransfer.effectAllowed = 'move';
                    e.originalEvent.dataTransfer.setData('text/plain', $row.data('group-id'));
                    $row.addClass('dragging');
                });
                $row.on('dragend', function(){
                    if ($dragging) { $dragging.removeClass('dragging'); $dragging = null; }
                });
                $row.on('dragover', function(e){
                    if (!$dragging) return;
                    e.preventDefault();
                    const $target = $(this);
                    if ($target.is($dragging)) return;
                    const rect = this.getBoundingClientRect();
                    const after = (e.originalEvent.clientY - rect.top) > (rect.height / 2);
                    if (after) { $target.after($dragging); } else { $target.before($dragging); }
                });
            });
        }

        function collectOrder(){
            return $tbody.find('tr.draggable-group').map(function(){ return $(this).data('group-id'); }).get();
        }

        function renumberInputs(){
            let pos = 10;
            $tbody.find('tr.draggable-group').each(function(){
                $(this).find('.group-sort-input').val(pos);
                pos += 10;
            });
        }

        attachDnD();

        $('#saveGroupOrderBtn').on('click', function(){
            const order = collectOrder();
            const $btn = $(this);
            const prev = $btn.html();
            $btn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងរក្សាទុក...');
            $.ajax({
                type: 'POST', url: 'admin_attendance.php', dataType: 'json',
                data: { ajax_action: 'reorder_user_groups', 'ordered_group_ids[]': order },
                success: function(res){
                    if (res.status === 'success') { showAjaxMessage('success', res.message || 'Saved'); renumberInputs(); }
                    else { showAjaxMessage('error', res.message || 'បរាជ័យក្នុងការរក្សាទុកលំដាប់'); }
                },
                error: function(xhr){ showAjaxMessage('error', 'បញ្ហា Network/Server: ' + (xhr.responseText || '')); },
                complete: function(){ $btn.prop('disabled', false).html(prev); }
            });
        });
    })();

    // ===== Drag & Drop reorder for Groups in Users list (group headers) =====
    (function(){
        const $tbody = $('#usersTableBody');
        if ($tbody.length === 0) return; // Only on users list page

        let draggingGroupId = null;
        let $dragBlock = $();
        let saveTimer = null; // debounce timer

        function getBlockByGroupId(gid){
            const $header = $tbody.find(`tr.group-header[data-group-id="${gid}"]`).first();
            if ($header.length === 0) return $();
            const $rows = [$header.get(0)];
            let $next = $header.next();
            while ($next.length && !$next.hasClass('group-header')) {
                $rows.push($next.get(0));
                $next = $next.next();
            }
            return $($rows); // correct jQuery wrapping
        }

        function collectGroupHeaderIds(){
            return $tbody.find('tr.group-header').map(function(){ return $(this).data('group-id'); }).get();
        }

        function autoSaveOrder(){
            const ids = collectGroupHeaderIds().filter(id => parseInt(id,10) > 0);
            if (ids.length === 0) return;
            $.ajax({
                type: 'POST', url: 'admin_attendance.php', dataType: 'json',
                data: { ajax_action: 'reorder_user_groups', 'ordered_group_ids[]': ids },
                success: function(res){
                    if (res.status === 'success') { showAjaxMessage('success', res.message || 'បានរក្សាទុកលំដាប់'); }
                    else { showAjaxMessage('error', res.message || 'បរាជ័យក្នុងការរក្សាទុកលំដាប់'); }
                },
                error: function(xhr){ showAjaxMessage('error', 'បញ្ហា Network/Server: ' + (xhr.responseText || '')); }
            });
        }

        function scheduleSave(){
            if (saveTimer) clearTimeout(saveTimer);
            saveTimer = setTimeout(autoSaveOrder, 400); // wait a bit for user to finish dragging adjustments
        }

        $tbody.on('dragstart', 'tr.group-header', function(e){
            const $h = $(this);
            draggingGroupId = $h.data('group-id');
            $dragBlock = getBlockByGroupId(draggingGroupId);
            e.originalEvent.dataTransfer.effectAllowed = 'move';
            e.originalEvent.dataTransfer.setData('text/plain', String(draggingGroupId));
            $dragBlock.addClass('dragging');
        });

        $tbody.on('dragend', 'tr.group-header', function(){
            if ($dragBlock && $dragBlock.length) $dragBlock.removeClass('dragging');
            $dragBlock = $(); draggingGroupId = null;
            scheduleSave(); // ensure save even if drop event not triggered
        });

        $tbody.on('dragover', 'tr.group-header', function(e){
            if (!draggingGroupId) return;
            const $targetHeader = $(this);
            const targetId = $targetHeader.data('group-id');
            if (!targetId || targetId === draggingGroupId) return;
            e.preventDefault();
            const rect = this.getBoundingClientRect();
            const after = (e.originalEvent.clientY - rect.top) > (rect.height/2);
            let $targetBlock = getBlockByGroupId(targetId);
            if (!$targetBlock.length) return;
            $dragBlock.detach();
            if (after) { $targetBlock.last().after($dragBlock); }
            else { $targetBlock.first().before($dragBlock); }
            scheduleSave(); // debounce save during movement
        });

        // Keep drop handler for compatibility (older browsers)
        $tbody.on('drop', 'tr.group-header', function(e){
            if (!draggingGroupId) return; e.preventDefault(); scheduleSave();
        });
    })();

    // Reports list: Select all / per-row checkbox
    $(document).on('change', '#selectAllReports', function() {
        const checked = $(this).is(':checked');
        $('.report-select').prop('checked', checked).trigger('change');
    });
    $(document).on('change', '.report-select', function() {
        const any = $('.report-select:checked').length > 0;
        $('#deleteSelectedBtn').prop('disabled', !any);
    });

    // Click-to-highlight rows for easy manual counting
    function updateAttendanceSelectionInfo(){
        const count = $('#reportsTable tbody tr.attendance-selected').length;
        if (count > 0) {
            $('#attendanceSelectionInfo').show().html('បានជ្រើស <strong>'+count+'</strong>');
            $('#clearAttendanceSelection').show();
        } else {
            $('#attendanceSelectionInfo').hide();
            $('#clearAttendanceSelection').hide();
        }
    }
    $(document).on('click', '#reportsTable tbody tr[data-log-pk]', function(e){
        // Ignore clicks on interactive elements
        if ($(e.target).is('a, button, input, label, i, select, textarea') || $(e.target).closest('.dropdown-menu').length) return;
        $(this).toggleClass('attendance-selected');
        updateAttendanceSelectionInfo();
    });
    $(document).on('click', '#clearAttendanceSelection', function(){
        $('#reportsTable tbody tr.attendance-selected').removeClass('attendance-selected');
        updateAttendanceSelectionInfo();
    });

    // Bulk delete selected reports (attendance logs)
    $('#deleteSelectedBtn').on('click', function() {
        const ids = $('.report-select:checked').map(function(){ return $(this).data('id'); }).get().filter(Boolean);
        if (ids.length === 0) return;
        if (!confirm(`តើអ្នកពិតជាចង់លុប ${ids.length} សំណុទ្ធ (records) ជាចុងវិញទេ? នេះអាចមិនអាចស្ដារឡើងវិញបាន។`)) return;
        const $btn = $(this);
        const prev = $btn.html();
        $btn.prop('disabled', true).html('<i class="fa-solid fa-spinner fa-spin"></i> កំពុងលុប...');
        $.ajax({
            type: 'POST', url: 'admin_attendance.php', dataType: 'json',
            data: { ajax_action: 'bulk_delete_logs', log_ids: ids },
            success: function(res) {
                if (res.status === 'success') {
                    showAjaxMessage('success', res.message || 'Deleted selected records.');
                    // Remove deleted rows from DOM if returned
                    if (res.deleted_ids && Array.isArray(res.deleted_ids)) {
                        res.deleted_ids.forEach(function(did){
                            $(`tr[data-log-pk="${did}"]`).remove();
                        });
                    }
                    // disable button
                    $('#deleteSelectedBtn').prop('disabled', true);
                } else {
                    showAjaxMessage('error', res.message || 'Failed to delete selected records.');
                }
            },
            error: function(xhr) { showAjaxMessage('error', 'បញ្ហា Network/Server: ' + (xhr.responseText || '')); },
            complete: function() { $btn.prop('disabled', false).html(prev); }
        });
    });

    // New handler for the toggle switch
    $(document).on('change', '.toggle-status-switch', function() {
        const $checkbox = $(this); // Save the context of the checkbox
        const fieldId = $checkbox.data('field-id');
        const isActive = $checkbox.is(':checked') ? 1 : 0;

        $.ajax({
            type: 'POST',
            url: 'admin_attendance.php',
            data: {
                ajax_action: 'toggle_request_field_status',
                field_id: fieldId,
                is_active: isActive
            },
            dataType: 'json',
            success: function(response) {
                // Show a small success message that fades out, but don't revert the switch
                if (response.status === 'success') {
                    // Optional: Show a brief success notification if you want
                    // showAjaxMessage('success', response.message);
                } else {
                    // If the server reports an error, show the message and revert the switch
                    showAjaxMessage('error', response.message);
                    $checkbox.prop('checked', !isActive);
                }
            },
            error: function() {
                // If the AJAX call itself fails, show a generic error and revert the switch
                showAjaxMessage('error', 'Error changing status.');
                $checkbox.prop('checked', !isActive);
            }
        });
    });

    // (Removed) Copy user name to clipboard handler

    // Department filter tabs handler
    $('#departmentTabs .nav-link').on('click', function(e) {
        e.preventDefault();
        const dept = $(this).data('dept');
        if (!dept) return;

        // Update active state
        $('#departmentTabs .nav-link').removeClass('active');
        $(this).addClass('active');

        // Get current URL parameters
        const urlParams = new URLSearchParams(window.location.search);
        urlParams.set('filter_department', dept);

        // Navigate to new URL
        const newUrl = window.location.pathname + '?' + urlParams.toString();
        window.location.href = newUrl;
    });

    // Late summary: toggle dropdowns and jump to specific report rows
    $(document).on('click', '[data-toggle="late-dd"], .late-toggle-btn', function(){
        const target = $(this).data('target');
        if (!target) return;
        const $panel = $(target);
        const isOpen = $panel.is(':visible');
        // Close other open panels
        $('.late-dd, .late-details-panel').not($panel).slideUp(120);
        $panel.slideToggle(120);
        $(this).attr('aria-expanded', !isOpen);

        // Update button icon rotation
        const $icon = $(this).find('i.fa-chevron-down');
        if ($icon.length) {
            if (isOpen) {
                $icon.css('transform', 'rotate(0deg)');
            } else {
                $icon.css('transform', 'rotate(180deg)');
            }
        }
    });

    // Reports table: action dropdown toggle
    $(document).on('click', '.action-toggle-btn', function(){
        const $container = $(this).closest('.action-dropdown-container');
        const $menu = $container.find('.action-dropdown-menu');
        const isOpen = $menu.is(':visible');

        // Close other open action menus
        $('.action-dropdown-menu').not($menu).slideUp(120);

        // Toggle this menu
        $menu.slideToggle(120);

        // Update button icon rotation
        const $icon = $(this).find('i.fa-circle-chevron-down');
        if ($icon.length) {
            if (isOpen) {
                $icon.css('transform', 'rotate(0deg)');
            } else {
                $icon.css('transform', 'rotate(180deg)');
            }
        }
    });
    $(document).on('click', 'a.late-jump', function(e){
        e.preventDefault();
        const id = parseInt($(this).data('log-id'), 10) || 0;
        let $row = null;
        if (id) {
            $row = $(`#reportsTable tr[data-log-pk="${id}"]`);
        }
        if (!$row || $row.length === 0) {
            const emp = $(this).data('emp-id');
            const dt = $(this).data('dt');
            if (emp && dt) {
                $row = $(`#reportsTable tr[data-emp="${emp}"][data-dt="${dt}"]`);
            }
        }
        if ($row.length) {
            // Scroll container to row if table is inside a wrapper
            const $wrap = $('#reportsTableWrapper');
            if ($wrap.length) {
                const top = $row.position().top + $wrap.scrollTop();
                $wrap.animate({ scrollTop: Math.max(top - 80, 0) }, 250);
            } else {
                $row[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
            $row.addClass('row-pulse');
            setTimeout(()=> $row.removeClass('row-pulse'), 1600);
        }
    });

    // Reports fullscreen toggle
    (function(){
        const $btn = $('#toggleReportsFullscreen');
        if ($btn.length === 0) return;
        const $wrap = $('#reportsTableWrapper');
        function setIcon(isFull){
            const i = $btn.find('i');
            i.toggleClass('fa-expand', !isFull);
            i.toggleClass('fa-compress', isFull);
            $btn.attr('title', isFull ? 'បិទ Fullscreen' : 'បង្ហាញពេញអេក្រង់');
        }
        function isNativeFs(){ return !!(document.fullscreenElement || document.webkitFullscreenElement || document.msFullscreenElement); }
        function requestFs(el){
            if (el.requestFullscreen) return el.requestFullscreen();
            if (el.webkitRequestFullscreen) return el.webkitRequestFullscreen();
            if (el.msRequestFullscreen) return el.msRequestFullscreen();
        }
        function exitFs(){
            if (document.exitFullscreen) return document.exitFullscreen();
            if (document.webkitExitFullscreen) return document.webkitExitFullscreen();
            if (document.msExitFullscreen) return document.msExitFullscreen();
        }
        // Inject all data rows when entering fullscreen; revert on exit
        function applyAllData(){
            if ($wrap.data('allDataApplied')) return; // already applied
            const dhCount = parseInt($wrap.data('dh-count'),10) || 0;
            const $exportRows = $('#reportsTableExport tbody tr');
            if ($exportRows.length === 0) return;
            const $tbody = $('#reportsTable tbody');
            $wrap.data('originalPaginatedHtml', $tbody.html());
            let newHtml='';
            // Build rows using current visible headers order so cloned table columns match exactly
            const headers = getHeaders();
            $exportRows.each(function(){
                const $r=$(this);
                const logPk = $r.data('log-pk') || 0;
                const dt = $r.data('dt') || '';
                if (!logPk && logPk !== 0) return;
                newHtml += '<tr data-log-pk="'+logPk+'" data-dt="'+dt+'">';

                headers.forEach(function(h){
                    // Handle special 'select' column
                    if (h.key === 'select') {
                        newHtml += '<td class="col-select" style="text-align:center;"><input type="checkbox" class="report-select" data-id="'+logPk+'"></td>';
                        return;
                    }

                    // Find matching cell in export row by class
                    const $cell = $r.find('.col-'+h.key).first();
                    const cls = 'col-'+h.key + ( $cell.attr('class') ? ' ' + $cell.attr('class') : '' );
                    const inner = ($cell.length) ? $cell.html() : '';

                    // For noted column, ensure contenteditable and data-log-id
                    if (h.key === 'noted') {
                        newHtml += '<td class="'+cls+' noted-cell" contenteditable="true" data-log-id="'+logPk+'">'+inner+'</td>';
                    } else {
                        newHtml += '<td class="'+cls+'">'+inner+'</td>';
                    }
                });

                newHtml += '</tr>';
            });
            $tbody.html(newHtml);
            $wrap.data('allDataApplied', true);
        }
        function revertPaginated(){
            if (!$wrap.data('allDataApplied')) return;
            const original = $wrap.data('originalPaginatedHtml');
            if (original != null){ $('#reportsTable tbody').html(original); }
            $wrap.removeData('allDataApplied').removeData('originalPaginatedHtml');
        }
        $btn.on('click', function(){
            const wrapperEl = $wrap.get(0);
            if (!wrapperEl) return;
            if (!isNativeFs() && !$wrap.hasClass('fullscreen-fallback')) {
                // Try native first
                const p = requestFs(wrapperEl);
                if (p && typeof p.then === 'function') {
                    p.catch(function(){ $wrap.addClass('fullscreen-fallback'); setIcon(true); $('body').addClass('no-scroll'); applyAllData(); });
                } else {
                    // No promise support -> fallback
                    $wrap.addClass('fullscreen-fallback'); setIcon(true); $('body').addClass('no-scroll'); applyAllData();
                }
            } else {
                // Exit
                if (isNativeFs()) { exitFs(); }
                $wrap.removeClass('fullscreen-fallback'); setIcon(false); $('body').removeClass('no-scroll'); revertPaginated();
            }
        });
        // Update icon when native fullscreen changes (user presses ESC)
        ['fullscreenchange','webkitfullscreenchange','MSFullscreenChange'].forEach(evt => {
            document.addEventListener(evt, function(){
                const active = isNativeFs();
                if (active){
                    // entering native fullscreen
                    setIcon(true); $('body').addClass('no-scroll'); applyAllData();
                } else {
                    // exiting
                    $wrap.removeClass('fullscreen-fallback'); $('body').removeClass('no-scroll'); setIcon(false); revertPaginated();
                }
            });
        });
    })();

    // Auto-update polling for reports has been disabled to avoid automatic reloads.
    // If you need to re-enable polling later, restore the fetchReportsData IIFE above.
});
</script>

<script>
// Sidebar Requests badge: live pending count updater
(function(){
    function getAjaxUrl(){ return window.location.pathname; }
    function ensureBadge(){
        const link = document.querySelector('.sidebar a[href*="?page=requests"]');
        if (!link) return { link: null, badge: null };
        let badge = link.querySelector('.notification-badge');
        if (!badge) {
            badge = document.createElement('span');
            badge.className = 'notification-badge';
            badge.style.display = 'none';
            link.appendChild(badge);
        }
        return { link, badge };
    }
    async function refresh(){
        const { link, badge } = ensureBadge();
        if (!link || !badge) return;
        try {
            const fd = new FormData();
            fd.append('ajax_action','get_request_counts');
            const res = await fetch(getAjaxUrl(), { method: 'POST', body: fd, credentials: 'same-origin' });
            if (!res.ok) return;
            const json = await res.json();
            if (json && json.status === 'success' && json.data){
                const pending = Number(json.data.Pending || 0);
                if (pending > 0){
                    const prev = badge.textContent;
                    const next = pending > 99 ? '99+' : String(pending);
                    if (badge.style.display === 'none' || prev !== next) {
                        badge.textContent = next;
                        badge.style.display = 'inline-flex';
                        badge.classList.remove('badge-pulse');
                        void badge.offsetWidth; // reflow to restart animation
                        badge.classList.add('badge-pulse');
                    } else {
                        badge.textContent = next;
                        badge.style.display = 'inline-flex';
                    }
                } else {
                    badge.style.display = 'none';
                }
            }
        } catch(e) { /* ignore */ }
    }
    document.addEventListener('DOMContentLoaded', function(){
        refresh();
        setInterval(refresh, 60000);
        document.addEventListener('visibilitychange', function(){ if (!document.hidden) refresh(); });
    });
})();
</script>

<!-- Global Admin Loader (overlay) -->
<style>
#adminGlobalLoader{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:radial-gradient(ellipse at center, rgba(255,255,255,0.92) 0%, rgba(255,255,255,0.78) 55%, rgba(245,247,250,0.55) 100%);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);z-index:8000;transition:opacity .18s ease}
#adminGlobalLoader.fadeout{opacity:0}
#adminGlobalLoader .agl-box{display:flex;flex-direction:column;align-items:center;gap:14px;padding:26px 34px;border-radius:24px;background:linear-gradient(145deg,#ffffff 0%,#f4f8ff 55%,#eef3fb 100%);box-shadow:0 18px 48px -8px rgba(20,60,120,0.18),0 2px 6px rgba(20,60,120,0.08),inset 0 1px 0 rgba(255,255,255,0.7)}
#adminGlobalLoader .agl-progress{width:210px;height:8px;border-radius:6px;background:rgba(10,132,255,0.14);position:relative;overflow:hidden;box-shadow:inset 0 1px 2px rgba(0,0,0,0.15),0 1px 0 rgba(255,255,255,0.6)}
#adminGlobalLoader .agl-progress-bar{position:absolute;inset:0;left:0;top:0;height:100%;width:0%;background:linear-gradient(90deg,#0a84ff,#52a8ff,#0a84ff);background-size:220% 100%;animation:aglBarMove 1.6s linear infinite;filter:drop-shadow(0 0 4px rgba(10,132,255,0.5))}
@keyframes aglBarMove{0%{background-position:0 0}100%{background-position:200% 0}}
#adminGlobalLoader .agl-spinner{position:relative;width:86px;height:86px}
#adminGlobalLoader .agl-spinner .ring{position:absolute;inset:0;border:7px solid transparent;border-top-color:#0a84ff;border-radius:50%;animation:aglSpin 1.05s linear infinite}
#adminGlobalLoader .agl-spinner .ring.r2{border-top-color:#52a8ff;animation-duration:1.55s;filter:drop-shadow(0 0 6px rgba(10,132,255,0.45))}
#adminGlobalLoader .agl-spinner .ring.r3{border-top-color:#b3d9ff;animation-duration:2.1s;filter:blur(0.5px);opacity:.65}
#adminGlobalLoader .agl-spinner .dot{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);width:20px;height:20px;border-radius:50%;background:linear-gradient(135deg,#0a84ff,#0060d1);box-shadow:0 6px 18px rgba(10,132,255,0.45),0 0 0 6px rgba(10,132,255,0.15);animation:aglPulse 1.9s ease-in-out infinite}
#adminGlobalLoader .agl-text{font-family:'Kantumruy Pro',system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#143451;font-weight:700;letter-spacing:.3px;font-size:1.05rem;text-align:center;text-shadow:0 1px 0 rgba(255,255,255,0.6)}
@keyframes aglSpin{to{transform:rotate(360deg)}}
@keyframes aglPulse{0%,100%{transform:translate(-50%,-50%) scale(1);opacity:1}50%{transform:translate(-50%,-50%) scale(.7);opacity:.78}}
@media (max-width:640px){#adminGlobalLoader .agl-box{width:78%;padding:24px 20px}.agl-text{font-size:.95rem}}
</style>
<div id="adminGlobalLoader" aria-hidden="true" role="status" aria-live="polite">
    <div class="agl-box">
        <div class="agl-spinner" aria-hidden="true">
            <span class="ring r1"></span>
            <span class="ring r2"></span>
            <span class="ring r3"></span>
            <span class="dot"></span>
        </div>
        <div class="agl-text" id="adminGlobalLoaderText">កំពុងដំណើរការ...</div>
        <div class="agl-progress" aria-hidden="true"><div class="agl-progress-bar" id="adminGlobalProgressBar"></div></div>
    </div>
</div>

<script>
var _aglProgTimer=null,_aglTarget=0,_aglCurr=0,_aglDone=false;
function _aglTick(){
    if(_aglDone) return;
    _aglCurr += ( _aglTarget - _aglCurr ) * 0.18 + 0.55; // faster ease + base increment
    if(_aglCurr > _aglTarget) _aglCurr = _aglTarget;
    var bar=document.getElementById('adminGlobalProgressBar');
    if(bar){ bar.style.width=_aglCurr+'%'; }
    if(_aglCurr >= 98){ _aglDone=true; }
    if(!_aglDone) _aglProgTimer = requestAnimationFrame(_aglTick);
}
// Enhanced state & safety timers
var _aglVisible=false,_aglLastShow=0,_aglForceHideTimer=null,_aglAjaxDelayTimer=null,_aglBatchTimer=null,_aglActiveAjax=0;
var _aglMinDisplay=140,_aglMaxDisplay=8000; // ms (shorter minimum & lower max to avoid long spins)
// Thresholds for grouping multiple ajax calls
var _aglShowDelay=280,_aglBatchWindow=200; // increased delay to avoid flash on fast AJAX
function showAdminLoader(message){
    var el=document.getElementById('adminGlobalLoader'); if(!el) return;
    var textEl=document.getElementById('adminGlobalLoaderText');
    // If already visible just update message (avoid flicker / re-init)
    if(_aglVisible){ if(message && textEl){ textEl.textContent=message; } return; }
    if(message && textEl){ textEl.textContent=message; }
    _aglVisible=true; _aglLastShow=performance.now();
    _aglCurr=0; _aglTarget=82; _aglDone=false; cancelAnimationFrame(_aglProgTimer);
    clearTimeout(_aglForceHideTimer);
    var bar=document.getElementById('adminGlobalProgressBar'); if(bar){ bar.style.width='0%'; }
    el.classList.remove('fadeout'); el.style.display='flex';
    _aglProgTimer=requestAnimationFrame(_aglTick);
    // staged target bumps (earlier and higher for perceived speed)
    setTimeout(function(){ if(!_aglDone){ _aglTarget=94; }},400);
    setTimeout(function(){ if(!_aglDone){ _aglTarget=97; }},800);
    // Force hide fallback (never leave overlay stuck)
    _aglForceHideTimer=setTimeout(function(){ if(_aglVisible){ forceHideAdminLoader(); } }, _aglMaxDisplay);
}
function forceHideAdminLoader(){
    var el=document.getElementById('adminGlobalLoader'); if(!el) return;
    _aglTarget=100; _aglDone=true; cancelAnimationFrame(_aglProgTimer);
    el.style.display='none'; el.classList.remove('fadeout');
    _aglVisible=false; clearTimeout(_aglForceHideTimer); _aglForceHideTimer=null;
}
function hideAdminLoader(){
    if(!_aglVisible) return; // nothing to hide
    var el=document.getElementById('adminGlobalLoader'); if(!el) return;
    var elapsed=performance.now()-_aglLastShow;
    var delay=Math.max(0,_aglMinDisplay - elapsed); // ensure minimum visible time
    // Drive progress to completion during wait
    _aglTarget=100; _aglDone=false;
    setTimeout(function(){
        el.classList.add('fadeout');
        setTimeout(function(){
            el.style.display='none'; el.classList.remove('fadeout'); _aglDone=true;
            _aglVisible=false; clearTimeout(_aglForceHideTimer); _aglForceHideTimer=null;
        },180);
    }, delay);
}
// Smarter auto show/hide for jQuery Ajax (batch multiple calls, skip trivial)
if(window.jQuery){(function($){
    function scheduleShow(){
        clearTimeout(_aglAjaxDelayTimer);
        _aglAjaxDelayTimer=setTimeout(function(){
            if(_aglActiveAjax>0){ showAdminLoader('កំពុងផ្ទុកទិន្នន័យ...'); }
        }, _aglShowDelay);
    }
    $(document).ajaxSend(function(evt,jqXHR,settings){
        // Skip loader for lightweight or explicitly bypassed requests
        if(settings && settings.headers && settings.headers['X-Bypass-Loader']==='1') return;
        if(settings && settings.type==='GET' && (settings.url||'').match(/fetch_(latest|requests|counts)/)) {
            // polling endpoints kept silent unless long-running
            jqXHR.setRequestHeader('X-Bypass-Loader','1');
            return;
        }
        _aglActiveAjax++;
        // Batch multiple near-simultaneous ajax calls
        if(!_aglBatchTimer){
            _aglBatchTimer=setTimeout(function(){ _aglBatchTimer=null; if(_aglActiveAjax>0){ scheduleShow(); } }, _aglBatchWindow);
        }
    });
    function ajaxComplete(){
        _aglActiveAjax = Math.max(0,_aglActiveAjax-1);
        if(_aglActiveAjax===0){
            clearTimeout(_aglAjaxDelayTimer); _aglAjaxDelayTimer=null;
            hideAdminLoader();
        }
    }
    $(document).ajaxSuccess(ajaxComplete);
    $(document).ajaxError(function(){ ajaxComplete(); });
    $(document).ajaxComplete(function(){ ajaxComplete(); });
})(jQuery);}
// Hide on various lifecycle events
document.addEventListener('DOMContentLoaded', function(){ hideAdminLoader(); });
window.addEventListener('load', function(){ hideAdminLoader(); });
window.addEventListener('pageshow', function(){ hideAdminLoader(); });
</script>

<script>
// Bind loader ONLY to real full-page navigations — NOT dropdowns, tabs, modals, etc.
(function(){
    /**
     * Returns true ONLY if clicking this <a> will cause the browser
     * to navigate away from the current page (full page load).
     */
    function isRealNavigation(a) {
        if (!a || a.tagName !== 'A') return false;

        // External tab → browser handles it, no overlay needed
        if (a.target && a.target === '_blank') return false;

        const href = (a.getAttribute('href') || '').trim();

        // Empty / pure hash anchors (#, #section) — scroll only, no navigation
        if (!href || href === '#' || /^#[^/]/.test(href)) return false;

        // Non-http schemes
        if (/^(javascript|tel|mailto|sms|data):/i.test(href)) return false;

        // Bootstrap 4/5 toggle attributes → UI-only interaction
        if (a.dataset.toggle || a.dataset.bsToggle ||
            a.dataset.target || a.dataset.bsTarget ||
            a.dataset.dismiss || a.dataset.bsDismiss ||
            a.getAttribute('data-bs-toggle') ||
            a.getAttribute('data-toggle')) return false;

        // Element is inside a Bootstrap dropdown menu, tab-content, modal, sidebar toggle etc.
        if (a.closest('.dropdown-menu') ||
            a.closest('[role="menu"]') ||
            a.closest('.modal') ||
            a.closest('.offcanvas') ||
            a.classList.contains('dropdown-item') ||
            a.classList.contains('dropdown-toggle') ||
            a.classList.contains('nav-link') ||   // Bootstrap tab nav links (handled by JS)
            a.classList.contains('ajax-delete-link') ||
            a.classList.contains('no-loader')) return false;

        // aria roles that indicate UI-only
        const role = (a.getAttribute('role') || '').toLowerCase();
        if (role === 'button' || role === 'tab' || role === 'menuitem') return false;

        // Has onclick that likely returns false (JS-driven, not real nav)
        // We can't inspect the function, but if defaultPrevented fires we cancel anyway

        // Must contain admin_attendance.php or a relative path (same-site)
        // Absolute external URLs → let browser handle without loader
        if (/^https?:\/\//i.test(href) && !href.includes(window.location.hostname)) return false;

        return true;
    }

    var _navLoaderTimer = null;

    // Capture link clicks early to show loader before navigation
    document.addEventListener('click', function(e) {
        const a = e.target && e.target.closest ? e.target.closest('a') : null;
        if (!a || !isRealNavigation(a)) return;

        // Don't show loader if the event is going to be prevented (e.g. AJAX intercept)
        // Use a tiny delay so preventDefault() by other listeners fires first
        _navLoaderTimer = setTimeout(function() {
            if (!e.defaultPrevented) {
                showAdminLoader('កំពុងផ្ទុកទំព័រ...');
                // Safety hide if page doesn't unload (file download, server error, js cancelled it)
                setTimeout(function(){ hideAdminLoader(); }, 10000);
            }
        }, 30); // 30ms — enough for other listeners to preventDefault, tiny for UX
    }, true);

    // Non-AJAX form submits
    document.addEventListener('submit', function(e) {
        const form = e.target;
        if (!(form && form.tagName === 'FORM')) return;
        // Skip AJAX forms
        if (form.classList && (form.classList.contains('ajax-form') || form.dataset.ajaxForm)) return;
        // Skip forms handled by submitAjaxForm / submitAjaxFormWithFile
        if (form.querySelector('[name="ajax_action"]')) return;

        showAdminLoader('កំពុងដំណើរការ...');
        setTimeout(function(){ hideAdminLoader(); }, 15000);
    }, true);

    // Safety net: show on actual browser unload
    window.addEventListener('beforeunload', function() {
        try { if (typeof showAdminLoader === 'function') showAdminLoader('កំពុងផ្ទុកទំព័រ...'); } catch(_){}
    });
})();
</script>


    <!-- QRCode Styling Library -->
    <script src="https://cdn.jsdelivr.net/npm/qr-code-styling@1.6.0/lib/qr-code-styling.js"></script>
    <script>
    // QR Designer logic
    let qrStylingInstance = null;
    let qrDesignData = { text: '', name: '' };

    function openQrDesigner(btnEl) {
        const data = btnEl.getAttribute('data-qr');
        const locName = btnEl.getAttribute('data-locname') || 'Location';
        qrDesignData.text = data || '';
        qrDesignData.name = locName;
        document.getElementById('qrDesignLocationName').value = locName;
        // Initialize if needed
        const preview = document.getElementById('qrPreview');
        preview.innerHTML = '';
        qrStylingInstance = new QRCodeStyling({
            width: 300,
            height: 300,
            type: 'canvas',
            data: qrDesignData.text,
            image: null,
            dotsOptions: { type: 'dots', color: '#000000' },
            cornersSquareOptions: { type: 'dot', color: '#000000' },
            cornersDotOptions: { type: 'dot', color: '#000000' },
            backgroundOptions: { color: '#ffffff' }
        });
        qrStylingInstance.append(preview);
        document.getElementById('qrDesignerModal').style.display = 'block';
    }

    function updateQrDesign() {
        if (!qrStylingInstance) return;
        const bodyType = document.getElementById('qrBodyShape').value || 'dots';
        const eyeOuter = document.getElementById('qrEyeOuter').value || 'dot';
        const eyeInner = document.getElementById('qrEyeInner').value || 'dot';
        qrStylingInstance.update({
            data: qrDesignData.text,
            dotsOptions: { type: bodyType, color: '#000000' },
            cornersSquareOptions: { type: eyeOuter, color: '#000000' },
            cornersDotOptions: { type: eyeInner, color: '#000000' }
        });
    }

    document.addEventListener('change', function(e) {
        if (e.target && (e.target.id === 'qrBodyShape' || e.target.id === 'qrEyeOuter' || e.target.id === 'qrEyeInner')) {
            updateQrDesign();
        }
    });

    document.getElementById('qrLogoInput').addEventListener('change', function(e) {
        const file = e.target.files && e.target.files[0];
        if (!file) { if (qrStylingInstance) qrStylingInstance.update({ image: null }); return; }
        const reader = new FileReader();
        reader.onload = function() {
            if (qrStylingInstance) {
                qrStylingInstance.update({ image: reader.result });
            }
        };
        reader.readAsDataURL(file);
    });

    document.getElementById('qrDownloadPngBtn').addEventListener('click', function() {
        if (!qrStylingInstance) return;
        const filename = `QR_${qrDesignData.name.replace(/\s+/g,'_')}.png`;
        qrStylingInstance.download({ name: filename, extension: 'png' });
    });

    document.getElementById('qrDownloadSvgBtn').addEventListener('click', function() {
        if (!qrStylingInstance) return;
        const filename = `QR_${qrDesignData.name.replace(/\s+/g,'_')}.svg`;
        qrStylingInstance.download({ name: filename, extension: 'svg' });
    });
    </script>
    <!-- ExcelJS and FileSaver for modern .xlsx export -->
    <script src="https://cdn.jsdelivr.net/npm/exceljs@4.4.0/dist/exceljs.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/file-saver@2.0.5/dist/FileSaver.min.js"></script>
    <style>
    /* Styles for draggable rows and inline editing */
    .draggable-field-row.dragging { opacity: 0.45; }
    .draggable-field-row.placeholder { outline: 2px dashed #3498db; background: #f8fbfd; }
    .field-label-display { cursor: text; }
    .field-label-input { box-sizing: border-box; padding: 6px; }

    /* Late employees section styles */
    .late-employee-card:hover {
        transform: translateY(-2px);
        box-shadow: 0 8px 20px rgba(239,68,68,0.15);
    }

    .late-toggle-btn:hover {
        background: #f3f4f6 !important;
        border-color: #d1d5db !important;
        color: #374151 !important;
    }

    .late-toggle-btn[aria-expanded="true"] i.fa-chevron-down {
        transform: rotate(180deg);
    }

    /* Action dropdown styles */
    .action-dropdown-container {
        position: relative;
        display: inline-block;
    }

    .action-toggle-btn {
        width: 32px;
        height: 32px;
        border: 1px solid #e5e7eb;
        background: #f9fafb;
        border-radius: 8px;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
        transition: all 0.2s ease;
        color: #6b7280;
        padding: 0;
        margin: 0;
    }

    .action-toggle-btn:hover {
        background: #f3f4f6 !important;
        border-color: #d1d5db !important;
        color: #374151 !important;
    }

    .action-toggle-btn[aria-expanded="true"] i.fa-circle-chevron-down {
        transform: rotate(180deg);
    }

    .action-dropdown-menu {
        position: absolute;
        top: 100%;
        right: 0;
        background: white;
        border: 1px solid #e5e7eb;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.15);
        z-index: 1000;
        min-width: 120px;
        padding: 8px 0;
        margin-top: 4px;
    }

    .action-dropdown-menu .btn {
        width: 100%;
        border: none;
        border-radius: 0;
        background: transparent;
        color: #374151;
        text-align: left;
        padding: 8px 16px;
        margin: 0;
        font-size: 0.875rem;
    }

    .action-dropdown-menu .btn:hover {
        background: #f3f4f6;
        color: #1f2937;
    }

    /* Column visibility styles */
    .column-visibility-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 12px;
        margin-top: 15px;
    }

    .column-visibility-item {
        background: #f8fafc;
        border: 1px solid #e2e8f0;
        border-radius: 8px;
        padding: 12px;
        transition: all 0.2s ease;
    }

    .column-visibility-item:hover {
        background: #f1f5f9;
        border-color: #cbd5e1;
    }

    .column-visibility-label {
        display: flex;
        align-items: center;
        gap: 10px;
        margin: 0;
        cursor: pointer;
        font-weight: 500;
        color: #374151;
        font-size: 14px;
    }

    .column-visibility-label input[type="checkbox"] {
        width: 18px;
        height: 18px;
        accent-color: #3b82f6;
        cursor: pointer;
    }

    .column-visibility-label span {
        flex: 1;
        font-size: 13px;
        color: #6b7280;
    }

    .dynamic-fields-visibility {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
        gap: 12px;
        margin-top: 10px;
    }
    </style>

    <script>
    (function(){
        const tableBody = document.getElementById('userFieldsList');
        if (!tableBody) return;

        let dragSrcRow = null;

        function onDragStart(e) {
            dragSrcRow = this;
            this.classList.add('dragging');
            e.dataTransfer.effectAllowed = 'move';
            try { e.dataTransfer.setData('text/plain', this.dataset.fieldId); } catch (err) {}
        }
        function onDragEnd() { this.classList.remove('dragging'); removePlaceholders(); }

        function removePlaceholders(){
            const ph = tableBody.querySelectorAll('.placeholder');
            ph.forEach(p=>p.classList.remove('placeholder'));
        }

        function onDragOver(e) {
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            const row = getRowFromEvent(e);
            if (!row || row === dragSrcRow) return;
            // mark nearest
            removePlaceholders();
            row.classList.add('placeholder');
        }

        function onDrop(e) {
            e.stopPropagation();
            const row = getRowFromEvent(e);
            if (!row || !dragSrcRow) return;
            if (row === dragSrcRow) return;
            // insert before placeholder row
            tableBody.insertBefore(dragSrcRow, row);
            removePlaceholders();
            sendNewOrder();
        }

        function getRowFromEvent(e){
            let el = e.target;
            while (el && el !== tableBody && el.nodeName !== 'TR') el = el.parentNode;
            return (el && el.nodeName === 'TR') ? el : null;
        }

        function sendNewOrder(){
            const ids = Array.from(tableBody.querySelectorAll('tr[data-field-id]')).map(r=>r.dataset.fieldId);
            const fd = new FormData();
            fd.append('ajax_action', 'reorder_user_fields');
            ids.forEach(id=>fd.append('ordered_field_ids[]', id));
            fetch(window.location.pathname + window.location.search, { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(r=>r.json())
            .then(json=>{ if (json && json.status === 'success') { showAjaxMessage('success', json.message || 'Order saved'); } else { showAjaxMessage('error', json.message || 'Order save failed'); } })
            .catch(err=>{ showAjaxMessage('error', 'Network error while saving order'); });
        }

        // Attach drag handlers
        tableBody.querySelectorAll('tr.draggable-field-row').forEach(row=>{
            row.addEventListener('dragstart', onDragStart);
            row.addEventListener('dragend', onDragEnd);
            row.addEventListener('dragover', onDragOver);
            row.addEventListener('drop', onDrop);
        });

        // Inline label editing
        tableBody.addEventListener('click', function(e){
            const lbl = e.target.closest('.field-label-display');
            if (!lbl) return;
            const cell = lbl.parentNode;
            const input = cell.querySelector('.field-label-input');
            lbl.style.display = 'none'; input.style.display = '';
            input.focus(); input.select();
        });

        tableBody.addEventListener('keydown', function(e){
            if (e.target && e.target.classList && e.target.classList.contains('field-label-input')){
                if (e.key === 'Enter') { e.preventDefault(); e.target.blur(); }
                if (e.key === 'Escape') { e.target.value = e.target.previousElementSibling.textContent; e.target.blur(); }
            }
        });

        tableBody.addEventListener('blur', function(e){
            if (!(e.target && e.target.classList && e.target.classList.contains('field-label-input'))) return;
            const input = e.target; const newLabel = input.value.trim();
            const row = input.closest('tr'); const fid = row && row.dataset.fieldId;
            const display = row.querySelector('.field-label-display');
            input.style.display = 'none'; display.style.display = '';
            if (!fid) return;
            if (newLabel === display.textContent) return; // nothing changed
            const fd = new FormData(); fd.append('ajax_action','update_user_field'); fd.append('field_id', fid); fd.append('field_label', newLabel);
            // include required state
            const req = row.querySelector('.field-required-checkbox'); if (req) fd.append('is_required', req.checked?1:0);
            fetch(window.location.pathname + window.location.search, { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(r=>r.json()).then(json=>{
                if (json && json.status === 'success') { display.textContent = newLabel; showAjaxMessage('success', json.message || 'Field updated'); }
                else { showAjaxMessage('error', json.message || 'Update failed'); }
            }).catch(()=> showAjaxMessage('error','Network error while updating field'));
        }, true);

        // Toggle required checkbox
        tableBody.addEventListener('change', function(e){
            if (!(e.target && e.target.classList && e.target.classList.contains('field-required-checkbox'))) return;
            const chk = e.target; const row = chk.closest('tr'); const fid = row && row.dataset.fieldId;
            if (!fid) return;
            const fd = new FormData(); fd.append('ajax_action','update_user_field'); fd.append('field_id', fid); fd.append('field_label', row.querySelector('.field-label-input').value || row.querySelector('.field-label-display').textContent); fd.append('is_required', chk.checked?1:0);
            fetch(window.location.pathname + window.location.search, { method: 'POST', body: fd, credentials: 'same-origin' })
            .then(r=>r.json()).then(json=>{
                if (json && json.status === 'success') { showAjaxMessage('success', json.message || 'Field updated'); }
                else { showAjaxMessage('error', json.message || 'Update failed'); }
            }).catch(()=> showAjaxMessage('error','Network error while updating field'));
        });

    })();
    </script>

    <!-- Actions dropdown toggling -->
    <script>
    (function(){
        function closeAll(){
            document.querySelectorAll('.user-actions-dropdown .dropdown-menu.open').forEach(function(m){ m.classList.remove('open'); });
            // Also close action dropdown menus
            document.querySelectorAll('.action-dropdown-menu').forEach(function(m){ m.style.display = 'none'; });
            document.querySelectorAll('.action-toggle-btn').forEach(function(btn){
                btn.querySelector('i.fa-circle-chevron-down').style.transform = 'rotate(0deg)';
            });
        }
        document.addEventListener('click', function(e){
            var toggle = e.target.closest && e.target.closest('.user-actions-dropdown .dropdown-toggle');
            if (toggle){
                var wrap = toggle.closest('.user-actions-dropdown');
                if (!wrap) return;
                var menu = wrap.querySelector('.dropdown-menu');
                if (!menu) return;
                // close others first
                document.querySelectorAll('.user-actions-dropdown .dropdown-menu.open').forEach(function(m){ if(m!==menu) m.classList.remove('open'); });
                menu.classList.toggle('open');
                e.preventDefault();
                e.stopPropagation();
                return;
            }
            // Item clicked
            if (e.target.closest && e.target.closest('.user-actions-dropdown .dropdown-item')){
                closeAll();
                return; // allow original handlers (onclick / ajax) to proceed
            }
            // Outside click
            if (!e.target.closest || !e.target.closest('.user-actions-dropdown')){
                closeAll();
            }
        });
        document.addEventListener('keydown', function(e){ if(e.key==='Escape'){ closeAll(); } });
    })();

    // Column visibility functionality
    (function(){
        const COLUMN_VISIBILITY_KEY = 'attendance_report_column_visibility';

        // Default column visibility settings
        const defaultColumns = {
            'show_column_checkbox': true,
            'show_column_employee_id': true,
            'show_column_name': true,
            'show_column_action_type': true,
            'show_column_date': true,
            'show_column_time': true,
            'show_column_status': true,
            'show_column_late_reason': true,
            'show_column_actions': true
        };

        // Load column visibility preferences from localStorage
        function loadColumnVisibility() {
            try {
                const saved = localStorage.getItem(COLUMN_VISIBILITY_KEY);
                return saved ? JSON.parse(saved) : defaultColumns;
            } catch (e) {
                console.warn('Failed to load column visibility settings:', e);
                return defaultColumns;
            }
        }

        // Save column visibility preferences to localStorage
        function saveColumnVisibility(settings) {
            try {
                localStorage.setItem(COLUMN_VISIBILITY_KEY, JSON.stringify(settings));
            } catch (e) {
                console.warn('Failed to save column visibility settings:', e);
            }
        }

        // Apply column visibility to the table
        function applyColumnVisibility() {
            const settings = loadColumnVisibility();
            const table = document.getElementById('attendance-reports-table');

            if (!table) return;

            // Get all table headers
            const headers = table.querySelectorAll('thead th');
            const rows = table.querySelectorAll('tbody tr');

            // Column mapping (index to setting key)
            const columnMap = {
                0: 'show_column_checkbox',      // Checkbox column
                1: 'show_column_employee_id',   // Employee ID
                2: 'show_column_name',          // Name
                // Dynamic fields will be handled separately
                // Action Type, Date, Time, Status, Late Reason, Actions
            };

            // Apply visibility to static columns
            headers.forEach((header, index) => {
                const settingKey = columnMap[index];
                if (settingKey) {
                    const isVisible = settings[settingKey] !== false;
                    header.style.display = isVisible ? '' : 'none';

                    // Apply to corresponding cells in all rows
                    rows.forEach(row => {
                        const cell = row.cells[index];
                        if (cell) {
                            cell.style.display = isVisible ? '' : 'none';
                        }
                    });
                }
            });

            // Handle dynamic fields (custom user fields)
            const dynamicFieldHeaders = Array.from(headers).filter(header => header.classList.contains('dynamic-field-header'));
            dynamicFieldHeaders.forEach(header => {
                const fieldId = header.dataset.fieldId;
                const settingKey = `show_dynamic_field_${fieldId}`;
                const isVisible = settings[settingKey] !== false;

                header.style.display = isVisible ? '' : 'none';

                // Find corresponding column index for this dynamic field
                const headerIndex = Array.from(headers).indexOf(header);
                rows.forEach(row => {
                    const cell = row.cells[headerIndex];
                    if (cell) {
                        cell.style.display = isVisible ? '' : 'none';
                    }
                });
            });
        }

        // Initialize column visibility on page load
        function initColumnVisibility() {
            // Load current settings into form checkboxes
            const settings = loadColumnVisibility();

            Object.keys(settings).forEach(key => {
                const checkbox = document.querySelector(`input[name="${key}"]`);
                if (checkbox) {
                    checkbox.checked = settings[key];
                }
            });

            // Apply visibility to table
            applyColumnVisibility();
        }

        // Handle checkbox changes in settings
        document.addEventListener('change', function(e) {
            if (e.target.matches('input[name^="show_column_"], input[name^="show_dynamic_field_"]')) {
                const checkbox = e.target;
                const settingKey = checkbox.name;
                const isChecked = checkbox.checked;

                // Update localStorage
                const settings = loadColumnVisibility();
                settings[settingKey] = isChecked;
                saveColumnVisibility(settings);

                // Apply changes immediately
                applyColumnVisibility();

                // Show success message
                showAjaxMessage('success', 'Column visibility updated');
            }
        });

        // Initialize when DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', initColumnVisibility);
        } else {
            initColumnVisibility();
        }

        // Also initialize after AJAX table updates
        const originalFetch = window.fetch;
        window.fetch = function(...args) {
            return originalFetch.apply(this, args).then(response => {
                response.clone().text().then(text => {
                    if (text.includes('attendance-reports-table')) {
                        setTimeout(applyColumnVisibility, 100);
                    }
                });
                return response;
            });
        };
    })();
    </script>

    </script>


    <script>
    (function() {
        const searchBtn = document.getElementById('searchUserBtn');
        const idInput = document.getElementById('searchUserID');
        const nameInput = document.getElementById('searchUserName');

        if (!searchBtn || !idInput || !nameInput) return;

        function filterUsers() {
            const idQuery = idInput.value.toLowerCase().trim();
            const nameQuery = nameInput.value.toLowerCase().trim();
            const rows = document.querySelectorAll('#usersTableBody tr.user-row');

            rows.forEach(row => {
                const idText = (row.cells[1] ? row.cells[1].textContent : '').toLowerCase();
                const nameText = (row.cells[2] ? row.cells[2].textContent : '').toLowerCase();

                const matchesId = idQuery === '' || idText.includes(idQuery);
                const matchesName = nameQuery === '' || nameText.includes(nameQuery);

                if (matchesId && matchesName) {
                    row.style.display = '';
                } else {
                    row.style.display = 'none';
                }
            });

            // Handle group headers (hide group header if all its rows are hidden)
            const allRows = document.querySelectorAll('#usersTableBody tr');
            let lastGroupHeader = null;
            let hasVisibleInGroup = false;

            allRows.forEach(row => {
                if (row.classList.contains('group-header')) {
                    if (lastGroupHeader) {
                        lastGroupHeader.style.display = hasVisibleInGroup ? '' : 'none';
                    }
                    lastGroupHeader = row;
                    hasVisibleInGroup = false;
                } else if (!row.classList.contains('group-header') && row.style.display !== 'none') {
                    hasVisibleInGroup = true;
                }
            });
            if (lastGroupHeader) {
                lastGroupHeader.style.display = hasVisibleInGroup ? '' : 'none';
            }
        }

        searchBtn.addEventListener('click', filterUsers);
        idInput.addEventListener('input', filterUsers);
        nameInput.addEventListener('input', filterUsers);
    })();
    </script>

    <!-- Fullscreen Mode Script -->
    <script>
    (function(){
        const toggleBtn = document.getElementById('toggleReportsFullscreen');
        if (toggleBtn) {
            // Create Exit button
            let exitBtn = document.createElement('button');
            exitBtn.id = 'fullscreenExitBtn';
            exitBtn.type = 'button';
            exitBtn.innerHTML = '<i class="fa-solid fa-compress"></i> ចាកចេញ (Exit)';
            document.body.appendChild(exitBtn);

            // Toggle On
            toggleBtn.addEventListener('click', function() {
                document.body.classList.add('fullscreen-mode');
            });

            // Toggle Off (Exit)
            exitBtn.addEventListener('click', function() {
                document.body.classList.remove('fullscreen-mode');
            });

            // Allow ESC key to exit
            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && document.body.classList.contains('fullscreen-mode')) {
                    document.body.classList.remove('fullscreen-mode');
                }
            });
        }
    })();
    </script>
    <!-- Printable Report Area -->
    <div id="printableReportArea" style="display:none;"></div>

    <style>
    /* Printing Styles */
    @media print {
        body * { visibility: hidden !important; }
        #printableReportArea, #printableReportArea * { visibility: visible !important; }
        #printableReportArea {
            position: absolute;
            left: 0;
            top: 0;
            width: 100%;
            display: block !important;
            background: #fff;
        }
        @page { size: A4; margin: 10mm; }

        /* Ensure table styles carry over */
        .print-table th { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .print-table tr:nth-child(even) { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .print-title-block { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
        .print-subtitle-block { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
    }

    /* Report Layout Styles */
    #printableReportArea { font-family: 'Khmer OS Siemreap', 'Siemreap', sans-serif; }
    .print-header { text-align: center; margin-bottom: 20px; }
    .print-logo-text { font-family: 'Khmer OS Moul', 'Khmer OS Siemreap', sans-serif; color: #b7950b; font-weight: bold; font-size: 28px; margin-bottom: 2px; }
    .print-company { font-weight: bold; font-size: 20px; color: #b7950b; margin-bottom: 15px; letter-spacing: 2px; }

    .print-title-block { background: #1e2d4a !important; color: #ffc107 !important; padding: 15px; text-align: center; border-radius: 4px; margin-bottom: 5px; }
    .print-title-block h1 { margin: 0; font-size: 24px; font-weight: bold; font-family: 'Khmer OS Moul', sans-serif; }

    .print-subtitle-block { background: #1e2d4a !important; color: #fff !important; padding: 10px; text-align: center; border-radius: 4px; margin-bottom: 20px; }
    .print-info { color: #f1c40f !important; font-size: 15px; font-weight: bold; margin-bottom: 5px; }
    .print-range { font-size: 13px; }

    .print-table { width: 100%; border-collapse: collapse; margin-bottom: 20px; border: 1.5px solid #000; }
    .print-table thead tr:first-child th { background: #ffc107 !important; color: #000 !important; border: 1px solid #000; padding: 8px 5px; font-size: 13px; font-weight: bold; }
    .print-table thead tr:nth-child(2) th { background: #ffc107 !important; color: #000 !important; border: 1px solid #000; padding: 5px; font-size: 11px; }
    .print-table td { border: 1px solid #000; padding: 6px 5px; font-size: 12px; text-align: center; }
    .print-table td:nth-child(3), .print-table td:nth-child(5) { text-align: left; }
    .print-table tr:nth-child(even) { background-color: #fff9e6 !important; }
    .print-table tfoot td { background: #ffc107 !important; color: #000 !important; font-weight: bold; padding: 8px; border: 1px solid #000; }

    .print-footer { display: flex; justify-content: space-between; margin-top: 40px; padding: 0 40px; }
    .sig-block { text-align: center; width: 40%; }
    .sig-title { font-weight: bold; margin-bottom: 80px; font-size: 14px; line-height: 1.6; }
    .sig-name { font-weight: bold; border-top: 1px solid #000; display: inline-block; width: 220px; padding-top: 5px; margin-top: 10px; }
    .sig-date { font-size: 12px; margin-top: 5px; }

    .print-date-location { text-align: right; width: 100%; font-size: 12px; margin-bottom: 20px; padding-right: 40px; }
    </style>

    <script>
    function printReport(type) {
        const area = document.getElementById('printableReportArea');
        if (!area) return;

        let title = '';
        let tableId = '';
        let rangeStr = '';
        let deptStr = '';

        if (type === 'late') {
            title = 'របាយការណ៍បុគ្គលិកមកយឺត';
            tableId = 'lateReportSummaryTable';
        } else if (type === 'forgotten') {
            title = 'របាយការណ៍បុគ្គលិកភ្លេចស្កេន';
            tableId = 'forgottenScanReportTable';
        }

        const sourceTable = document.getElementById(tableId);
        if (!sourceTable) { alert('សូមជ្រើសរើសទិន្នន័យដើម្បីបង្ហាញរបាយការណ៍សិន។'); return; }

        // Get info from filters
        const startDate = document.querySelector('input[name="start_date"]')?.value || '';
        const endDate = document.querySelector('input[name="end_date"]')?.value || '';
        const activeTab = document.querySelector('.nav-link.active');
        const dept = activeTab ? activeTab.textContent.trim() : '';

        rangeStr = `គិតចាប់ពីថ្ងៃទី ${startDate} ដល់ថ្ងៃទី ${endDate}`;
        deptStr = `សម្រាប់បុគ្គលិក${dept}`;

        // Build HTML
        let html = `
            <div class="print-header">
                <div class="print-logo-text">វណ្ណ វណ្ណ ខេមបូឌា</div>
                <div class="print-company">VAN VAN CAMBODIA</div>
            </div>
            <div class="print-title-block">
                <h1>${title}</h1>
            </div>
            <div class="print-subtitle-block">
                <div class="print-info">${deptStr}</div>
                <div class="print-range">${rangeStr}</div>
            </div>
            <table class="print-table">
                ${sourceTable.innerHTML}
            </table>

            <div class="print-date-location">
                ថ្ងៃអង្គារ ៦កើត ខែបុស្ស ឆ្នាំរោង ឆស័ក ព.ស.២៥៦៩<br>
                រាជធានីភ្នំពេញ, ថ្ងៃទី .... ខែ .... ឆ្នាំ ២០២៦
            </div>

            <div class="print-footer">
                <div class="sig-block">
                    <div class="sig-title">ប្រធាននាយកដ្ឋានធនធានមនុស្ស និងរដ្ឋបាល</div>
                    <div class="sig-name">................................................</div>
                    <div class="sig-date">ហេង សាន</div>
                </div>
                <div class="sig-block">
                    <div class="sig-title">ប្រតិបត្តិករដោយ<br>រៀបចំដោយ</div>
                    <div class="sig-name">................................................</div>
                    <div class="sig-date">រឿង សាវុធ</div>
                </div>
            </div>
        `;

        area.innerHTML = html;
        window.print();
    }

    function exportTableToExcel(tableID, filename = ''){
        var downloadLink;
        var dataType = 'application/vnd.ms-excel';
        var tableSelect = document.getElementById(tableID);
        if (!tableSelect) return;

        var tableHTML = tableSelect.outerHTML.replace(/ /g, '%20');

        // Specify file name
        filename = filename ? filename + '.xls' : 'excel_data.xls';

        // Create download link element
        downloadLink = document.createElement("a");

        document.body.appendChild(downloadLink);

        if(navigator.msSaveOrOpenBlob){
            var blob = new Blob(['\ufeff', tableHTML], {
                type: dataType
            });
            navigator.msSaveOrOpenBlob( blob, filename);
        } else {
            // Create a link to the file
            downloadLink.href = 'data:' + dataType + ', ' + tableHTML;

            // Setting the file name
            downloadLink.download = filename;

            //triggering the function
            downloadLink.click();
        }
    }

    document.getElementById('exportExcelBtn')?.addEventListener('click', function() {
        exportTableToExcel('reportsTableExport', 'Attendance_Report');
    });

    // --- PWA & Web Push (Admin) ---
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('sw.js')
          .then(registration => {
            console.log('ServiceWorker registered:', registration);
            // Ask for Notification permission
            if ('Notification' in window) {
              Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                  subscribeUserToPush(registration);
                }
              });
            }
          });
      });
    }

    async function subscribeUserToPush(registration) {
        const publicVapidKey = 'BGBSU2jW6Olk8tnMgy_4UsqLajIj3VWy-SLC8A4HswFJkEFvJybNrRKNAYG2LkHM-jQJ6TDVccJ1qLUTW41T-gs';
        try {
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: urlBase64ToUint8Array(publicVapidKey)
            });
            const fd = new FormData();
            fd.append('ajax_action', 'save_push_subscription');
            fd.append('subscription', JSON.stringify(subscription));
            await fetch('', { method: 'POST', body: fd });
        } catch (error) { console.error('Failed to subscribe to Push:', error); }
    }

    function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) { outputArray[i] = rawData.charCodeAt(i); }
        return outputArray;
    }
    </script>
</body>
</html>