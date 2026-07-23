<?php

error_reporting(0);
ini_set('display_errors', 0);

/**
 * VVC-HRM Centralized API Gateway (v2.0)
 * Unified landing point for all Mobile and Frontend requests.
 */
ob_start();

// 1. Headers & Environment
error_reporting(E_ALL);
ini_set('display_errors', 1);
date_default_timezone_set('Asia/Phnom_Penh');

header('Content-Type: application/json; charset=UTF-8');
header('Access-Control-Allow-Origin: *');

// Force UTF-8 encoding for internal functions
mb_internal_encoding('UTF-8');
mb_http_output('UTF-8');

// Disable mysqli exceptions to handle missing tables gracefully (return false instead of fatal error)
mysqli_report(MYSQLI_REPORT_OFF);
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit;
}

require_once __DIR__ . '/config.php';
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require_once __DIR__ . '/vendor/autoload.php';
}
require_once __DIR__ . '/webpush_functions.php';
require_once __DIR__ . '/notification_functions.php';
require_once __DIR__ . '/enterprise_helpers.php';
require_once __DIR__ . '/ai_tools.php';
require_once __DIR__ . '/ai_provider_openai.php';
require_once __DIR__ . '/ai_chat_service.php';
require_once __DIR__ . '/ai_image_service.php';

/**
 * Get connection to HRM settings database
 * @return mysqli|null
 */
function getHRMConnection() {
    if (!defined('HRM_DB_NAME')) return null;
    $conn = @new mysqli(HRM_DB_SERVER, HRM_DB_USERNAME, HRM_DB_PASSWORD, HRM_DB_NAME);
    if ($conn && $conn->connect_error) return null;
    if ($conn) {
        $conn->set_charset("utf8mb4");
        $conn->query("SET time_zone = '+07:00'");
    }
    return $conn;
}

/**
 * Calculate attendance streak (consecutive 'Good' scans)
 */
function getAttendanceStreak($mysqli, $eid) {
    // Fetch unique dates of 'Check-In' logs, most recent first
    // We only care about days they actually scanned
    $sql = "SELECT DATE(log_datetime) as log_date, status
            FROM checkin_logs
            WHERE employee_id = ? AND (action_type = 'Check-In' OR action_type = 'checkin')
            ORDER BY log_datetime DESC
            LIMIT 100";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) return 0;

    $stmt->bind_param("s", $eid);
    $stmt->execute();
    $res = $stmt->get_result();

    $streak = 0;
    $processed_dates = [];

    while ($row = $res->fetch_assoc()) {
        $date = $row['log_date'];
        if (isset($processed_dates[$date])) continue; // Only one scan per day counts

        if ($row['status'] === 'Good' || stripos($row['status'], 'Good') !== false) {
            $streak++;
            $processed_dates[$date] = true;
        } else {
            // If they have any other status (Late, etc.) on a day they worked, streak breaks
            break;
        }
    }
    $stmt->close();
    return $streak;
}

/**
 * Get Telegram Bot Token from various sources
 */
function getTelegramBotToken($mysqli, $eid = null) {
    // Priority 0: Always prefer Bot Token from HRM Admin Panel (settings_control.php)
    $hrm_db = getHRMConnection();
    if ($hrm_db) {
        $res_hrm = $hrm_db->query("SELECT bot_token FROM telegram_settings WHERE id = 1 LIMIT 1");
        if ($res_hrm && $row_hrm = $res_hrm->fetch_assoc()) {
            $token = $row_hrm['bot_token'];
            $hrm_db->close();
            if (!empty($token)) return $token;
        }
        $hrm_db->close();
    }

    // Priority 1: Check system_settings (Global override in main DB)
    $res = $mysqli->query("SELECT setting_value FROM system_settings WHERE setting_key = 'telegram_bot_token' LIMIT 1");
    if ($res && $row = $res->fetch_assoc()) {
        if (!empty($row['setting_value'])) return $row['setting_value'];
    }

    // Priority 2: Check app_scan_settings specifically for eid
    if ($eid) {
        $token = get_scan_setting('telegram_bot_token', null, $mysqli, $eid);
        if (!empty($token)) return $token;
    }

    // Priority 3: Check telegram_settings in main DB
    $res = $mysqli->query("SELECT bot_token FROM telegram_settings LIMIT 1");
    if ($res && $row = $res->fetch_assoc()) {
        if (!empty($row['bot_token'])) return $row['bot_token'];
    }

    // Priority 4: Constants
    return defined('TELEGRAM_BOT_TOKEN') ? TELEGRAM_BOT_TOKEN : '';
}

/**
 * មុខងារផ្ញើរបាយការណ៍ប្រចាំថ្ងៃទៅកាន់ Telegram Topic
 */
function sendDailyReportToTelegram($mysqli, $employee_id, $employee_name, $position, $content, $report_date, $direct_thread_id = null, $direct_chat_id = null) {
    // 1. Get Settings from app_scan_settings (New UI)
    $enabled_val = get_scan_setting('daily_report_telegram_enabled', '0', $mysqli, $employee_id);
    if ($enabled_val !== '1') {
        // Fallback to old table for transition
        $settings_res = $mysqli->query("SELECT * FROM daily_report_telegram_settings WHERE id = 1 LIMIT 1");
        $settings = $settings_res ? $settings_res->fetch_assoc() : null;
        if (!$settings || empty($settings['enabled'])) {
             error_log("Daily Report Telegram: Feature not enabled");
             return false;
        }
        $bot_token = $settings['bot_token'] ?? '';
        $chat_id_setting = $settings['group_id'] ?? '';
        $thread_id_setting = $settings['thread_id'] ?? '';
        $template = $settings['message_template'] ?? '';
    } else {
        $bot_token = get_scan_setting('daily_report_telegram_bot_token', '', $mysqli, $employee_id);
        $chat_id_setting = get_scan_setting('daily_report_telegram_chat_id', '', $mysqli, $employee_id);
        $thread_id_setting = get_scan_setting('daily_report_telegram_thread_id', '', $mysqli, $employee_id);
        $destinations_json = get_scan_setting('daily_report_telegram_destinations', '', $mysqli, $employee_id);
        $template = get_scan_setting('daily_report_telegram_template', '', $mysqli, $employee_id);
    }

    // 2. Resolve Bot Token (Fallback chain)
    if (empty($bot_token)) {
        $bot_token = getTelegramBotToken($mysqli, $employee_id);
    }

    if (empty($bot_token)) {
        error_log("Daily Report Telegram: No bot token configured");
        return false;
    }

    // 3. Prepare Destinations List
    $targets = []; // Array of ['chat_id' => ..., 'thread_id' => ...]

    // Case A: New JSON destinations list (Checklist from UI)
    if (!empty($destinations_json)) {
        $decoded = json_decode($destinations_json, true);
        if (is_array($decoded)) {
            foreach ($decoded as $dest) {
                if (!empty($dest['chat_id'])) {
                    $targets[] = [
                        'chat_id' => $dest['chat_id'],
                        'thread_id' => $dest['thread_id'] ?? ''
                    ];
                }
            }
        }
    }

    // Case B: Direct IDs from app (Priority)
    if (!empty($direct_chat_id)) {
        $targets = [[
            'chat_id' => $direct_chat_id,
            'thread_id' => $direct_thread_id ?? ''
        ]];
    }
    // Case C: Fallback to old single settings if no targets yet
    elseif (empty($targets)) {
        // Handle newline-separated or comma-separated lists for bulk sending in legacy fields
        $chat_ids = preg_split('/[\n,]+/', $chat_id_setting, -1, PREG_SPLIT_NO_EMPTY);
        $thread_ids = preg_split('/[\n,]+/', $thread_id_setting, -1, PREG_SPLIT_NO_EMPTY);

        if (!empty($chat_ids)) {
            foreach ($chat_ids as $index => $cid) {
                $targets[] = [
                    'chat_id' => trim($cid),
                    'thread_id' => isset($thread_ids[$index]) ? trim($thread_ids[$index]) : ''
                ];
            }
        }
    }

    if (empty($targets)) {
        error_log("Daily Report Telegram: No destination targets found");
        return false;
    }

    // 4. Fetch missing user details if needed
    if (empty($employee_name) || empty($position)) {
        $stmt_u = $mysqli->prepare("SELECT name, position, phone FROM users WHERE employee_id = ? LIMIT 1");
        if ($stmt_u) {
            $stmt_u->bind_param("s", $employee_id);
            $stmt_u->execute();
            $u_row = $stmt_u->get_result()->fetch_assoc();
            if ($u_row) {
                if (empty($employee_name)) $employee_name = $u_row['name'];
                if (empty($position)) $position = $u_row['position'];
                $phone = $u_row['phone'] ?? '';
            }
            $stmt_u->close();
        }
    }
    $email = $employee_id . "@vvc.com";

    // 5. Build message
    if (!empty($template)) {
        $message = $template;
        $replacements = [
            '{name}' => $employee_name,
            '{{name}}' => $employee_name,
            '{employee_id}' => $employee_id,
            '{{employee_id}}' => $employee_id,
            '{position}' => $position,
            '{{position}}' => $position,
            '{content}' => $content,
            '{{content}}' => $content,
            '{date}' => $report_date,
            '{{date}}' => $report_date,
            '{time}' => date('H:i:s A'),
            '{{time}}' => date('H:i:s A'),
            '{email}' => $email,
            '{{email}}' => $email,
            '{phone}' => $phone ?? '',
            '{{phone}}' => $phone ?? '',
        ];

        foreach ($replacements as $key => $val) {
            $message = str_ireplace($key, htmlspecialchars($val), $message);
        }
    } else {
        $message = "📋 <b>របាយការណ៍ប្រចាំថ្ងៃ</b>\n\n";
        $message .= "👤 <b>ឈ្មោះ:</b> " . htmlspecialchars($employee_name) . "\n";
        $message .= "🆔 <b>អត្តលេខ:</b> " . htmlspecialchars($employee_id) . "\n";
        if (!empty($position)) {
            $message .= "💼 <b>តួនាទី:</b> " . htmlspecialchars($position) . "\n";
        }
        $message .= "📧 <b>អ៊ីមែល:</b> " . htmlspecialchars($email) . "\n";
        $message .= "📅 <b>ថ្ងៃទី:</b> " . htmlspecialchars($report_date) . "\n";
        $message .= "⏰ <b>ពេលវេលា:</b> " . date('H:i:s A') . "\n\n";
        $message .= "📝 <b>ខ្លឹមសារ:</b>\n" . htmlspecialchars($content);
    }

    // 5. Send to all targets
    $success_count = 0;
    foreach ($targets as $target) {
        $url = 'https://api.telegram.org/bot' . $bot_token . '/sendMessage';
        $data = [
            'chat_id' => $target['chat_id'],
            'text' => $message,
            'parse_mode' => 'HTML',
        ];
        if (!empty($target['thread_id'])) {
            $data['message_thread_id'] = $target['thread_id'];
        }

        $options = [
            'http' => [
                'method'  => 'POST',
                'header'  => 'Content-Type: application/x-www-form-urlencoded',
                'content' => http_build_query($data),
                'timeout' => 5,
            ],
        ];
        $context = stream_context_create($options);
        $result = @file_get_contents($url, false, $context);

        if ($result !== false) {
            $res_arr = json_decode($result, true);
            if ($res_arr && $res_arr['ok']) $success_count++;
        }
    }

    return ($success_count > 0);
}

/**
 * មុខងារផ្ញើលិខិតបេសកកម្មទៅកាន់ Telegram
 */
function sendMissionTelegram($mysqli, $eid, $data) {
    // Reuse token/chat logic from existing settings
    $bot_token = getTelegramBotToken($mysqli, $eid);

    $chat_id = '';
    $res = $mysqli->query("SELECT setting_value FROM system_settings WHERE setting_key = 'telegram_chat_id' LIMIT 1");
    if ($res && $row = $res->fetch_assoc()) $chat_id = $row['setting_value'];
    if (empty($chat_id)) $chat_id = defined('TELEGRAM_CHAT_ID') ? TELEGRAM_CHAT_ID : '';

    if (empty($bot_token) || empty($chat_id)) return false;

    $message = "📜 <b>លិខិតបេសកកម្មថ្មី (New Mission)</b>\n\n";
    $message .= "👤 <b>អ្នកស្នើ:</b> " . htmlspecialchars($data['name'] ?? 'N/A') . " (" . htmlspecialchars($eid) . ")\n";
    $message .= "📍 <b>ទីតាំង:</b> " . htmlspecialchars($data['location'] ?? 'N/A') . "\n";
    $message .= "🎯 <b>គោលបំណង:</b> " . htmlspecialchars($data['purpose'] ?? 'N/A') . "\n";
    $message .= "📅 <b>កាលបរិច្ឆេទ:</b> " . htmlspecialchars($data['start_date'] ?? '') . " ដល់ " . htmlspecialchars($data['end_date'] ?? '') . "\n";
    if (!empty($data['start_time'])) $message .= "⏰ <b>ម៉ោង:</b> " . htmlspecialchars($data['start_time']) . " - " . htmlspecialchars($data['end_time'] ?? '') . "\n";
    $message .= "🚗 <b>មធ្យោបាយ:</b> " . htmlspecialchars($data['transport'] ?? 'N/A') . "\n";
    $message .= "📦 <b>សម្ភារៈ:</b> " . htmlspecialchars($data['materials'] ?? 'N/A') . "\n";
    $message .= "\n⏰ <b>ដាក់ជូននៅ:</b> " . date('d-m-Y H:i:s');

    $url = "https://api.telegram.org/bot$bot_token/sendMessage";
    $payload = ['chat_id' => $chat_id, 'text' => $message, 'parse_mode' => 'HTML'];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function check_api_rate_limit($mysqli) {
    // 1. Get client IP address
    $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $parts = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
        $ip = trim($parts[0]);
    } elseif (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    }

    // 2. Identify the request endpoint/action
    $action = $_GET['action'] ?? ($_POST['action'] ?? 'index');
    $now = time();
    $limit = 60; // Max 60 requests per minute
    
    // Auto-create rate limits table if not exists
    $mysqli->query("CREATE TABLE IF NOT EXISTS api_rate_limits (
        ip_address VARCHAR(45) NOT NULL,
        endpoint VARCHAR(255) NOT NULL,
        request_count INT NOT NULL DEFAULT 1,
        first_request_time INT NOT NULL,
        PRIMARY KEY (ip_address, endpoint)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // Retrieve current rate limit state
    $stmt = $mysqli->prepare("SELECT request_count, first_request_time FROM api_rate_limits WHERE ip_address = ? AND endpoint = ?");
    if ($stmt) {
        $stmt->bind_param("ss", $ip, $action);
        $stmt->execute();
        $result = $stmt->get_result();
        $row = $result ? $result->fetch_assoc() : null;
        $stmt->close();

        if ($row) {
            $count = (int)$row['request_count'];
            $first_time = (int)$row['first_request_time'];

            if (($now - $first_time) > 60) {
                // Window expired: Reset count and start a new 60s window
                $up_stmt = $mysqli->prepare("UPDATE api_rate_limits SET request_count = 1, first_request_time = ? WHERE ip_address = ? AND endpoint = ?");
                if ($up_stmt) {
                    $up_stmt->bind_param("iss", $now, $ip, $action);
                    $up_stmt->execute();
                    $up_stmt->close();
                }
            } else {
                // Inside window: Check if limit is exceeded
                if ($count >= $limit) {
                    http_response_code(429);
                    echo json_encode([
                        'success' => false,
                        'status' => 'error',
                        'message' => 'សំណើច្រើនពេកត្រូវបានផ្ញើក្នុងពេលតែមួយ។ សូមរង់ចាំមួយរយៈសិន មុននឹងព្យាយាមម្តងទៀត!'
                    ], JSON_UNESCAPED_UNICODE);
                    exit;
                }

                // Increment request count
                $up_stmt = $mysqli->prepare("UPDATE api_rate_limits SET request_count = request_count + 1 WHERE ip_address = ? AND endpoint = ?");
                if ($up_stmt) {
                    $up_stmt->bind_param("ss", $ip, $action);
                    $up_stmt->execute();
                    $up_stmt->close();
                }
            }
        } else {
            // First request in the window: Insert new record
            $ins_stmt = $mysqli->prepare("INSERT INTO api_rate_limits (ip_address, endpoint, request_count, first_request_time) VALUES (?, ?, 1, ?)");
            if ($ins_stmt) {
                $ins_stmt->bind_param("ssi", $ip, $action, $now);
                $ins_stmt->execute();
                $ins_stmt->close();
            }
        }
    }

    // 3. Garbage Collection: Clean up rate limits older than 1 hour (1% chance to run)
    if (rand(1, 100) === 42) {
        $expiry = $now - 3600;
        $mysqli->query("DELETE FROM api_rate_limits WHERE first_request_time < $expiry");
    }
}

// 2. Database Connection
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    echo json_encode(['success' => false, 'status' => 'error', 'message' => 'DB Connection Failed']);
    exit;
}
$mysqli->set_charset("utf8mb4");
$mysqli->query("SET time_zone = '+07:00'");

// Perform API Rate Limiting Check
check_api_rate_limit($mysqli);

// Auto-heal DB schema if core columns in users table are missing
$required_columns = [
    'global_max_tokens' => "INT DEFAULT 1",
    'system_role_label' => "VARCHAR(100) DEFAULT NULL",
    'email' => "VARCHAR(255) DEFAULT NULL",
    'avatar' => "VARCHAR(255) DEFAULT NULL",
    'username' => "VARCHAR(100) DEFAULT NULL",
    'joined_at' => "TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP"
];
foreach ($required_columns as $col => $definition) {
    $col_check = $mysqli->query("SHOW COLUMNS FROM users LIKE '$col'");
    if (!$col_check || $col_check->num_rows === 0) {
        @$mysqli->query("ALTER TABLE users ADD COLUMN $col $definition");
    }
}

ensure_enterprise_support_tables($mysqli);
process_due_notification_schedules($mysqli);

// 3. API Helpers
// Ensure notification tables for in-app alerts
function ensure_api_notification_tables($mysqli) {
    // Basic structural check and creation
    $mysqli->query("CREATE TABLE IF NOT EXISTS notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        title VARCHAR(255) NOT NULL,
        message TEXT NOT NULL,
        recipient_type ENUM('all', 'department', 'specific', 'role') DEFAULT 'all',
        recipient_info VARCHAR(255) DEFAULT NULL,
        expiry_date DATE DEFAULT NULL,
        image_url VARCHAR(255) DEFAULT NULL,
        sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $notif_cols = [];
    $notif_res = $mysqli->query("SHOW COLUMNS FROM notifications");
    if ($notif_res) {
        while ($notif_row = $notif_res->fetch_assoc()) {
            $notif_cols[$notif_row['Field']] = $notif_row;
        }
        $notif_res->close();
    }

    if (!isset($notif_cols['image_url'])) {
        $mysqli->query("ALTER TABLE notifications ADD COLUMN image_url VARCHAR(255) DEFAULT NULL AFTER expiry_date");
    }

    if (!isset($notif_cols['recipient_info'])) {
        $mysqli->query("ALTER TABLE notifications ADD COLUMN recipient_info VARCHAR(255) DEFAULT NULL AFTER recipient_type");
    }

    $recipient_type_def = strtolower($notif_cols['recipient_type']['Type'] ?? '');
    if ($recipient_type_def !== '' && strpos($recipient_type_def, "'role'") === false) {
        $mysqli->query("ALTER TABLE notifications MODIFY COLUMN recipient_type ENUM('all', 'department', 'specific', 'role') DEFAULT 'all'");
    }

    $mysqli->query("CREATE TABLE IF NOT EXISTS user_notifications (
        id INT AUTO_INCREMENT PRIMARY KEY,
        notification_id INT NOT NULL,
        employee_id VARCHAR(64) NOT NULL,
        is_read TINYINT(1) NOT NULL DEFAULT 0,
        read_at DATETIME DEFAULT NULL,
        KEY idx_notif_id (notification_id),
        KEY idx_emp_read (employee_id, is_read)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $mysqli->query("CREATE TABLE IF NOT EXISTS user_fcm_tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        fcm_token VARCHAR(255) NOT NULL,
        platform VARCHAR(30) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_fcm_token (fcm_token),
        KEY idx_employee_id (employee_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $user_fcm_col = $mysqli->query("SHOW COLUMNS FROM users LIKE 'fcm_token'");
    if ($user_fcm_col && $user_fcm_col->num_rows === 0) {
        $mysqli->query("ALTER TABLE users ADD COLUMN fcm_token VARCHAR(255) DEFAULT NULL");
    }
    if ($user_fcm_col) $user_fcm_col->close();
}

function ensure_app_scan_settings_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS app_scan_settings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL DEFAULT 'SYSTEM_WIDE',
        setting_key VARCHAR(100) NOT NULL,
        setting_value LONGTEXT,
        UNIQUE KEY uniq_scan (admin_id, setting_key)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

function ensure_payroll_biometric_records_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS payroll_biometric_records (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        employee_name VARCHAR(255) DEFAULT NULL,
        purpose VARCHAR(50) NOT NULL DEFAULT 'payroll',
        verification_count INT NOT NULL DEFAULT 1,
        first_verified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_verified_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        last_platform VARCHAR(80) DEFAULT NULL,
        last_auth_method VARCHAR(80) DEFAULT NULL,
        last_ip_address VARCHAR(45) DEFAULT NULL,
        last_user_agent VARCHAR(255) DEFAULT NULL,
        UNIQUE KEY uniq_emp_purpose (employee_id, purpose),
        KEY idx_last_verified (last_verified_at)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}

function ensure_daily_report_telegram_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS daily_report_telegram_settings (
        id INT PRIMARY KEY DEFAULT 1,
        enabled TINYINT DEFAULT 0,
        bot_token VARCHAR(255) DEFAULT NULL,
        group_id VARCHAR(50) DEFAULT NULL,
        thread_id VARCHAR(50) DEFAULT NULL,
        message_template TEXT DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // Auto-patch bot_token if missing
    $col_check = $mysqli->query("SHOW COLUMNS FROM daily_report_telegram_settings LIKE 'bot_token'");
    if ($col_check && $col_check->num_rows === 0) {
        $mysqli->query("ALTER TABLE daily_report_telegram_settings ADD COLUMN bot_token VARCHAR(255) DEFAULT NULL AFTER enabled");
    }
}

function ensure_daily_reports_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS daily_reports (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id VARCHAR(64) NOT NULL,
        position VARCHAR(100) DEFAULT NULL,
        report_date DATE NOT NULL,
        content LONGTEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_user (user_id),
        KEY idx_date (report_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");
}
function ensure_mission_letters_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS mission_letters (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        location VARCHAR(255) DEFAULT NULL,
        purpose VARCHAR(255) DEFAULT NULL,
        start_date DATE DEFAULT NULL,
        start_time VARCHAR(10) DEFAULT NULL,
        end_date DATE DEFAULT NULL,
        end_time VARCHAR(10) DEFAULT NULL,
        transport VARCHAR(255) DEFAULT NULL,
        materials VARCHAR(255) DEFAULT NULL,
        date_khmer TEXT DEFAULT NULL,
        status VARCHAR(20) DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_eid (employee_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // Patch columns if they don't exist
    $check = $mysqli->query("SHOW COLUMNS FROM mission_letters LIKE 'person1'");
    if ($check && $check->num_rows === 0) {
        $mysqli->query("ALTER TABLE mission_letters
            ADD COLUMN IF NOT EXISTS location VARCHAR(255) AFTER employee_id,
            ADD COLUMN IF NOT EXISTS purpose VARCHAR(255) AFTER location,
            ADD COLUMN IF NOT EXISTS start_time VARCHAR(10) AFTER start_date,
            ADD COLUMN IF NOT EXISTS end_time VARCHAR(10) AFTER end_date,
            ADD COLUMN IF NOT EXISTS transport VARCHAR(255) AFTER end_time,
            ADD COLUMN IF NOT EXISTS materials VARCHAR(255) AFTER transport,
            ADD COLUMN IF NOT EXISTS date_khmer TEXT AFTER materials,
            ADD COLUMN IF NOT EXISTS person1 VARCHAR(255), ADD COLUMN IF NOT EXISTS role1 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person2 VARCHAR(255), ADD COLUMN IF NOT EXISTS role2 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person3 VARCHAR(255), ADD COLUMN IF NOT EXISTS role3 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person4 VARCHAR(255), ADD COLUMN IF NOT EXISTS role4 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person5 VARCHAR(255), ADD COLUMN IF NOT EXISTS role5 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person6 VARCHAR(255), ADD COLUMN IF NOT EXISTS role6 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person7 VARCHAR(255), ADD COLUMN IF NOT EXISTS role7 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person8 VARCHAR(255), ADD COLUMN IF NOT EXISTS role8 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person9 VARCHAR(255), ADD COLUMN IF NOT EXISTS role9 VARCHAR(255),
            ADD COLUMN IF NOT EXISTS person10 VARCHAR(255), ADD COLUMN IF NOT EXISTS role10 VARCHAR(255)
        ");
    }
}

function ensure_meetings_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS meetings (
        id INT AUTO_INCREMENT PRIMARY KEY,
        topic VARCHAR(255) NOT NULL,
        department VARCHAR(100) DEFAULT NULL,
        meeting_date DATE DEFAULT NULL,
        description TEXT DEFAULT NULL,
        audio_path TEXT DEFAULT NULL,
        audio_file_path VARCHAR(255) DEFAULT NULL,
        audio_original_name VARCHAR(255) DEFAULT NULL,
        external_url TEXT DEFAULT NULL,
        photos LONGTEXT DEFAULT NULL,
        related_photos LONGTEXT DEFAULT NULL,
        transcript_text LONGTEXT DEFAULT NULL,
        created_by VARCHAR(64) DEFAULT NULL,
        summary LONGTEXT DEFAULT NULL,
        summary_json LONGTEXT DEFAULT NULL,
        summary_generated_at DATETIME DEFAULT NULL,
        transcript_provider VARCHAR(50) DEFAULT NULL,
        transcript_model VARCHAR(100) DEFAULT NULL,
        summary_provider VARCHAR(50) DEFAULT NULL,
        summary_model VARCHAR(100) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_dept (department),
        KEY idx_date (meeting_date)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // Manual check because ADD COLUMN IF NOT EXISTS requires modern MariaDB/MySQL
    $cols = []; $res = $mysqli->query("SHOW COLUMNS FROM meetings");
    if($res){
        while($r = $res->fetch_assoc()){ $cols[] = $r['Field']; }
        $res->close();
    }

    $missing = [
        'topic' => 'VARCHAR(255) NOT NULL',
        'department' => 'VARCHAR(100) DEFAULT NULL',
        'meeting_date' => 'DATE DEFAULT NULL',
        'description' => 'TEXT DEFAULT NULL',
        'audio_path' => 'TEXT DEFAULT NULL',
        'audio_file_path' => 'VARCHAR(255) DEFAULT NULL',
        'audio_original_name' => 'VARCHAR(255) DEFAULT NULL',
        'audio_url' => 'TEXT DEFAULT NULL',
        'external_url' => 'TEXT DEFAULT NULL',
        'photos' => 'LONGTEXT DEFAULT NULL',
        'related_photos' => 'LONGTEXT DEFAULT NULL',
        'transcript_text' => 'LONGTEXT DEFAULT NULL',
        'created_by' => 'VARCHAR(64) DEFAULT NULL',
        'summary' => 'LONGTEXT DEFAULT NULL',
        'summary_json' => 'LONGTEXT DEFAULT NULL',
        'summary_generated_at' => 'DATETIME DEFAULT NULL',
        'transcript_provider' => 'VARCHAR(50) DEFAULT NULL',
        'transcript_model' => 'VARCHAR(100) DEFAULT NULL',
        'summary_provider' => 'VARCHAR(50) DEFAULT NULL',
        'summary_model' => 'VARCHAR(100) DEFAULT NULL',
        'summary_job_id' => 'VARCHAR(64) DEFAULT NULL',
        'summary_job_status' => 'VARCHAR(30) DEFAULT NULL',
        'summary_job_message' => 'TEXT DEFAULT NULL',
        'summary_job_updated_at' => 'DATETIME DEFAULT NULL',
    ];

    foreach($missing as $col => $type) {
        if(!in_array($col, $cols)) {
            $mysqli->query("ALTER TABLE meetings ADD COLUMN $col $type");
        }
    }

}

function meeting_ai_string_list($value) {
    if (!is_array($value)) {
        return [];
    }

    $items = [];
    foreach ($value as $item) {
        $text = trim((string)$item);
        if ($text !== '') {
            $items[] = $text;
        }
    }
    return array_values(array_unique($items));
}

function meeting_ai_extract_json_payload($content) {
    $text = trim((string)$content);
    if ($text === '') {
        return null;
    }

    $decoded = json_decode($text, true);
    if (is_array($decoded)) {
        return $decoded;
    }

    $fenceStart = strpos($text, '{');
    $fenceEnd = strrpos($text, '}');
    if ($fenceStart === false || $fenceEnd === false || $fenceEnd <= $fenceStart) {
        return null;
    }

    $candidate = substr($text, $fenceStart, $fenceEnd - $fenceStart + 1);
    $decoded = json_decode($candidate, true);
    return is_array($decoded) ? $decoded : null;
}

function product_ai_find_json_object($content) {
    $text = trim((string)$content);
    if ($text === '') {
        return null;
    }

    $length = strlen($text);
    for ($start = 0; $start < $length; $start++) {
        if ($text[$start] !== '{') {
            continue;
        }

        $depth = 0;
        $inString = false;
        $escaped = false;
        for ($i = $start; $i < $length; $i++) {
            $char = $text[$i];

            if ($inString) {
                if ($escaped) {
                    $escaped = false;
                    continue;
                }
                if ($char === '\\') {
                    $escaped = true;
                    continue;
                }
                if ($char === '"') {
                    $inString = false;
                }
                continue;
            }

            if ($char === '"') {
                $inString = true;
                continue;
            }
            if ($char === '{') {
                $depth++;
                continue;
            }
            if ($char === '}') {
                $depth--;
                if ($depth === 0) {
                    $candidate = substr($text, $start, $i - $start + 1);
                    $decoded = json_decode($candidate, true);
                    if (is_array($decoded)) {
                        return [
                            'json' => $decoded,
                            'raw' => $candidate,
                        ];
                    }
                    break;
                }
            }
        }
    }

    return null;
}

function product_ai_clean_think_tags_recursive($data) {
    if (is_array($data)) {
        foreach ($data as $key => $val) {
            $data[$key] = product_ai_clean_think_tags_recursive($val);
        }
    } elseif (is_string($data)) {
        $data = preg_replace('/<think\b[^>]*>.*?<\/think>/is', '', $data);
        $data = preg_replace('/<think\b[^>]*>.*$/is', '', $data);
        $data = str_ireplace(['<think>', '</think>'], '', $data);
        $data = trim($data);
    }
    return $data;
}

function product_ai_heal_truncated_json($json_str) {
    $json_str = trim($json_str);
    if ($json_str === '') return '';

    // Check if it already parses successfully
    if (json_decode($json_str) !== null) {
        return $json_str;
    }

    $len = strlen($json_str);
    $in_string = false;
    $escaped = false;
    $stack = [];

    for ($i = 0; $i < $len; $i++) {
        $char = $json_str[$i];

        if ($in_string) {
            if ($escaped) {
                $escaped = false;
                continue;
            }
            if ($char === '\\') {
                $escaped = true;
                continue;
            }
            if ($char === '"') {
                $in_string = false;
            }
            continue;
        }

        if ($char === '"') {
            $in_string = true;
            continue;
        }

        if ($char === '{') {
            $stack[] = '}';
            continue;
        }
        if ($char === '[') {
            $stack[] = ']';
            continue;
        }
        if ($char === '}' || $char === ']') {
            if (!empty($stack)) {
                $last = end($stack);
                if ($last === $char) {
                    array_pop($stack);
                }
            }
            continue;
        }
    }

    // Heal the string
    $healed = $json_str;
    if ($in_string) {
        $healed .= '"';
    }

    // Close open structures
    while (!empty($stack)) {
        $close_char = array_pop($stack);
        $healed .= $close_char;
    }

    return $healed;
}

function product_ai_extract_json_payload($content) {
    $text = trim((string)$content);
    if ($text === '') {
        return null;
    }

    if (function_exists('ai_chat_fix_mojibake_text')) {
        $text = ai_chat_fix_mojibake_text($text);
    }

    $text = preg_replace('/^\xEF\xBB\xBF/', '', $text);
    
    // Strip closed think/reasoning tags
    $text = preg_replace('/<think\b[^>]*>.*?<\/think>/is', '', $text);
    $text = preg_replace('/<reasoning\b[^>]*>.*?<\/reasoning>/is', '', $text);
    
    // Handle unclosed think tags before JSON
    $firstBrace = strpos($text, '{');
    if ($firstBrace !== false) {
        $leadingText = substr($text, 0, $firstBrace);
        if (stripos($leadingText, '<think>') !== false || stripos($leadingText, '<reasoning>') !== false) {
            $text = substr($text, $firstBrace);
        }
    }

    $text = preg_replace('/^```(?:json)?\s*/i', '', trim((string)$text));
    $text = preg_replace('/\s*```\s*$/', '', trim((string)$text));
    $text = trim((string)$text);

    // Auto-heal truncated JSON text
    $healed = product_ai_heal_truncated_json($text);
    $decoded = json_decode($healed, true);
    if (is_array($decoded)) {
        return [
            'json' => product_ai_clean_think_tags_recursive($decoded),
            'raw' => $healed,
        ];
    }

    $parsed = product_ai_find_json_object($healed);
    if (is_array($parsed) && is_array($parsed['json'] ?? null)) {
        $parsed['json'] = product_ai_clean_think_tags_recursive($parsed['json']);
    }
    return $parsed;
}

function product_ai_fallback_parse_text($content) {
    $text = trim((string)$content);
    if ($text === '') {
        return null;
    }

    $text = preg_replace('/^\xEF\xBB\xBF/', '', $text);
    $text = preg_replace('/<think\b[^>]*>.*?<\/think>/is', '', $text);
    $text = preg_replace('/<reasoning\b[^>]*>.*?<\/reasoning>/is', '', $text);
    $cleaned = trim((string)$text);
    if ($cleaned === '') {
        return null;
    }

    $productName = 'ផលិតផល';
    $brand = '—';
    $country = 'កម្ពុជា';
    $flag = '🇰🇭';
    $category = 'ទូទៅ';

    if (preg_match('/["\']?(?:product_name|ឈ្មោះផលិតផល|ឈ្មោះ|product)["\']?\s*[:=]\s*["\']?([^"\'\n\r,]+)/iu', $cleaned, $m)) {
        $productName = trim(trim($m[1], '":,{}[]\''));
    } else {
        $lines = array_filter(array_map('trim', explode("\n", $cleaned)));
        foreach ($lines as $line) {
            $lineClean = preg_replace('/^[\#\*\-\s\d\.]+\s*/', '', $line);
            if (strpos($lineClean, ':') !== false) {
                $parts = explode(':', $lineClean, 2);
                $lineClean = trim($parts[1]);
            }
            $lineClean = trim(trim($lineClean, '":,{}[]\''));
            if (mb_strlen($lineClean) > 2 && mb_strlen($lineClean) < 80) {
                $productName = $lineClean;
                break;
            }
        }
    }

    if (preg_match('/["\']?(?:brand|ម៉ាក|យីហោ)["\']?\s*[:=]\s*["\']?([^"\'\n\r,]+)/iu', $cleaned, $m)) {
        $brand = trim(trim($m[1], '":,{}[]\''));
    }

    if (preg_match('/["\']?(?:country_of_origin|ប្រទេស|ប្រភព|origin)["\']?\s*[:=]\s*["\']?([^"\'\n\r,]+)/iu', $cleaned, $m)) {
        $country = trim(trim($m[1], '":,{}[]\''));
    }

    $benefits = [];
    $warnings = [];
    $usage = [];

    foreach (explode("\n", $cleaned) as $line) {
        $line = trim($line);
        if (preg_match('/^[\*\-\•\d\.]+\s+(.+)/u', $line, $m)) {
            $item = trim($m[1]);
            if (mb_strlen($item) > 3) {
                if (preg_match('/(ប្រយ័ត្ន|ហាម|កុំ|warning|caution)/iu', $item)) {
                    $warnings[] = $item;
                } else if (preg_match('/(ផលប្រយោជន៍|ប្រយោជន៍|ល្អ|benefit|good)/iu', $item)) {
                    $benefits[] = $item;
                } else {
                    $usage[] = $item;
                }
            }
        }
    }

    return [
        'product_name' => $productName,
        'brand' => $brand,
        'country_of_origin' => $country,
        'country_flag_emoji' => $flag,
        'category' => $category,
        'usage' => !empty($usage) ? array_slice($usage, 0, 5) : ['ប្រើប្រាស់តាមការណែនាំលើសំបកដប/ប្រអប់'],
        'benefits' => !empty($benefits) ? array_slice($benefits, 0, 5) : ['គុណភាពស្តង់ដារ និងមានសុវត្ថិភាព'],
        'warnings' => !empty($warnings) ? array_slice($warnings, 0, 3) : ['រក្សាទុកនៅកន្លែងស្ងួត និងត្រជាក់'],
        'ingredients_summary' => '—',
        'price_range_usd' => '—',
        'summary' => $cleaned,
    ];
}

function meeting_ai_parse_summary_payload($content) {
    $decoded = meeting_ai_extract_json_payload($content);
    if (!is_array($decoded)) {
        $fallback = trim((string)$content);
        return [
            'headline' => 'របាយការណ៍កិច្ចប្រជុំ',
            'overview' => $fallback,
            'key_points' => [],
            'decisions' => [],
            'action_items' => [],
            'next_steps' => [],
            'keywords' => [],
        ];
    }

    return [
        'headline' => trim((string)($decoded['headline'] ?? 'របាយការណ៍កិច្ចប្រជុំ')),
        'overview' => trim((string)($decoded['overview'] ?? $decoded['summary'] ?? '')),
        'key_points' => meeting_ai_string_list($decoded['key_points'] ?? []),
        'decisions' => meeting_ai_string_list($decoded['decisions'] ?? []),
        'action_items' => meeting_ai_string_list($decoded['action_items'] ?? []),
        'next_steps' => meeting_ai_string_list($decoded['next_steps'] ?? []),
        'keywords' => meeting_ai_string_list($decoded['keywords'] ?? []),
    ];
}

function meeting_ai_build_summary_text(array $analysis) {
    $sections = [];

    $headline = trim((string)($analysis['headline'] ?? ''));
    $overview = trim((string)($analysis['overview'] ?? ''));

    if ($headline !== '') {
        $sections[] = $headline;
    }
    if ($overview !== '') {
        $sections[] = "សេចក្តីសង្ខេប\n" . $overview;
    }

    $mapping = [
        'key_points' => 'ចំណុចសំខាន់ៗ',
        'decisions' => 'សេចក្តីសម្រេច',
        'action_items' => 'ការងារត្រូវអនុវត្ត',
        'next_steps' => 'ជំហានបន្ទាប់',
        'keywords' => 'ពាក្យគន្លឹះ',
    ];

    foreach ($mapping as $key => $label) {
        $items = meeting_ai_string_list($analysis[$key] ?? []);
        if (empty($items)) {
            continue;
        }
        $sections[] = $label . "\n- " . implode("\n- ", $items);
    }

    return trim(implode("\n\n", $sections));
}

function meeting_ai_get_worker_config() {
    $url = rtrim(trim((string)(defined('MEETING_AI_WORKER_URL') ? MEETING_AI_WORKER_URL : '')), '/');
    $token = trim((string)(defined('MEETING_AI_WORKER_TOKEN') ? MEETING_AI_WORKER_TOKEN : ''));
    $timeout = (int)(defined('MEETING_AI_WORKER_TIMEOUT') ? MEETING_AI_WORKER_TIMEOUT : 600);

    return [
        'enabled' => $url !== '',
        'url' => $url,
        'token' => $token,
        'timeout' => max(60, $timeout),
    ];
}

function meeting_ai_local_only_enabled() {
    $value = strtolower(trim((string)(defined('MEETING_AI_LOCAL_ONLY') ? MEETING_AI_LOCAL_ONLY : '0')));
    return in_array($value, ['1', 'true', 'yes', 'on'], true);
}

function meeting_ai_http_post_json($url, array $payload, array $headers = [], $timeout = 600) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array_merge([
        'Content-Type: application/json',
    ], $headers));
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_UNICODE));
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
    curl_setopt($ch, CURLOPT_TIMEOUT, max(60, (int)$timeout));

    $response = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false || $error !== '') {
        return [
            'ok' => false,
            'status' => $status,
            'message' => $error !== '' ? $error : 'Unknown cURL error',
        ];
    }

    $decoded = json_decode($response, true);
    if (!is_array($decoded)) {
        if ($status === 524) {
            return [
                'ok' => false,
                'status' => $status,
                'message' => 'Local AI worker timed out through Cloudflare (HTTP 524). The worker is reachable, but transcription/summarization took too long. Try a smaller Whisper model such as small or base, shorten the audio, or move the worker to a faster machine/VPS.',
                'raw' => $response,
            ];
        }
        $message = 'Invalid JSON response from worker.';
        $snippet = meeting_ai_compact_error_text($response);
        if ($snippet !== '') {
            $message .= ' ' . $snippet;
        }
        return [
            'ok' => false,
            'status' => $status,
            'message' => $message,
            'raw' => $response,
        ];
    }

    if ($status >= 400) {
        return [
            'ok' => false,
            'status' => $status,
            'message' => (string)($decoded['detail'] ?? $decoded['message'] ?? ('HTTP ' . $status)),
            'raw' => $decoded,
        ];
    }

    return [
        'ok' => true,
        'status' => $status,
        'data' => $decoded,
    ];
}

function meeting_ai_http_get_json($url, array $headers = [], $timeout = 600) {
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPGET, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 20);
    curl_setopt($ch, CURLOPT_TIMEOUT, max(30, (int)$timeout));

    $response = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($response === false || $error !== '') {
        return [
            'ok' => false,
            'status' => $status,
            'message' => $error !== '' ? $error : 'Unknown cURL error',
        ];
    }

    $decoded = json_decode($response, true);
    if (!is_array($decoded)) {
        $message = 'Invalid JSON response from worker.';
        $snippet = meeting_ai_compact_error_text($response);
        if ($snippet !== '') {
            $message .= ' ' . $snippet;
        }
        return [
            'ok' => false,
            'status' => $status,
            'message' => $message,
            'raw' => $response,
        ];
    }

    if ($status >= 400) {
        return [
            'ok' => false,
            'status' => $status,
            'message' => (string)($decoded['detail'] ?? $decoded['message'] ?? ('HTTP ' . $status)),
            'raw' => $decoded,
        ];
    }

    return [
        'ok' => true,
        'status' => $status,
        'data' => $decoded,
    ];
}

function meeting_ai_request_worker_summary(array $meeting, $existingTranscript = '') {
    $worker = meeting_ai_get_worker_config();
    if (empty($worker['enabled'])) {
        return [
            'attempted' => false,
            'success' => false,
            'message' => '',
        ];
    }

    $audioPath = trim((string)($meeting['audio_path'] ?? $meeting['audio_file_path'] ?? ''));
    $audioUrl = meeting_ai_public_audio_url($audioPath);
    $transcriptText = trim((string)$existingTranscript);
    $descriptionText = trim((string)($meeting['description'] ?? ''));

    if ($transcriptText === '' && $audioUrl === '' && $descriptionText !== '') {
        $transcriptText = $descriptionText;
    }

    if ($audioUrl === '' && $transcriptText === '') {
        return [
            'attempted' => false,
            'success' => false,
            'message' => '',
        ];
    }

    $payload = [
        'meeting_id' => (int)($meeting['id'] ?? 0),
        'topic' => trim((string)($meeting['topic'] ?? '')),
        'department' => trim((string)($meeting['department'] ?? '')),
        'description' => trim((string)($meeting['description'] ?? '')),
        'audio_url' => $audioUrl,
        'transcript_text' => $transcriptText,
        'language' => 'km',
    ];

    $headers = [];
    if ($worker['token'] !== '') {
        $headers[] = 'Authorization: Bearer ' . $worker['token'];
    }

    if (function_exists('set_time_limit')) {
        @set_time_limit(max(120, ((int)$worker['timeout']) + 60));
    }

    $jobResponse = meeting_ai_http_post_json(
        $worker['url'] . '/summarize-meeting-async',
        $payload,
        $headers,
        min(60, max(20, (int)$worker['timeout']))
    );

    if (!$jobResponse['ok'] && (int)($jobResponse['status'] ?? 0) === 404) {
        $jobResponse = meeting_ai_http_post_json(
            $worker['url'] . '/summarize-meeting',
            $payload,
            $headers,
            (int)$worker['timeout']
        );
        if (!$jobResponse['ok']) {
            return [
                'attempted' => true,
                'success' => false,
                'message' => (string)($jobResponse['message'] ?? 'AI worker request failed.'),
            ];
        }

        $data = is_array($jobResponse['data'] ?? null) ? $jobResponse['data'] : [];
        if (array_key_exists('success', $data) && !$data['success']) {
            return [
                'attempted' => true,
                'success' => false,
                'message' => (string)($data['message'] ?? 'AI worker could not summarize this meeting.'),
            ];
        }

        $analysis = is_array($data['analysis'] ?? null) ? $data['analysis'] : [];
        $summaryText = trim((string)($data['summary'] ?? ''));
        if ($summaryText === '' && !empty($analysis)) {
            $summaryText = meeting_ai_build_summary_text($analysis);
        }

        $transcript = trim((string)($data['transcript'] ?? $transcriptText));
        if ($summaryText === '' || $transcript === '') {
            return [
                'attempted' => true,
                'success' => false,
                'message' => 'AI worker returned an incomplete meeting summary.',
            ];
        }

        return [
            'attempted' => true,
            'success' => true,
            'summary' => $summaryText,
            'analysis' => $analysis,
            'transcript' => $transcript,
            'transcript_provider' => trim((string)($data['transcript_provider'] ?? 'local-worker')),
            'transcript_model' => trim((string)($data['transcript_model'] ?? 'faster-whisper')),
            'summary_provider' => trim((string)($data['summary_provider'] ?? 'local-worker')),
            'summary_model' => trim((string)($data['summary_model'] ?? 'ollama')),
        ];
    }

    if (!$jobResponse['ok']) {
        return [
            'attempted' => true,
            'success' => false,
            'message' => (string)($jobResponse['message'] ?? 'AI worker request failed.'),
        ];
    }

    $jobData = is_array($jobResponse['data'] ?? null) ? $jobResponse['data'] : [];
    $jobId = trim((string)($jobData['job_id'] ?? ''));
    if ($jobId === '') {
        return [
            'attempted' => true,
            'success' => false,
            'message' => 'AI worker did not return a job ID.',
        ];
    }

    $deadline = microtime(true) + max(60, (int)$worker['timeout']);
    $pollIntervalUs = 2000000;
    $lastMessage = 'Local AI worker is still processing this meeting.';

    while (microtime(true) < $deadline) {
        usleep($pollIntervalUs);
        $pollResponse = meeting_ai_http_get_json(
            $worker['url'] . '/jobs/' . rawurlencode($jobId),
            $headers,
            30
        );

        if (!$pollResponse['ok']) {
            if ((int)($pollResponse['status'] ?? 0) === 404) {
                continue;
            }
            return [
                'attempted' => true,
                'success' => false,
                'message' => (string)($pollResponse['message'] ?? 'AI worker job status check failed.'),
            ];
        }

        $statusData = is_array($pollResponse['data'] ?? null) ? $pollResponse['data'] : [];
        $status = strtolower(trim((string)($statusData['status'] ?? 'queued')));
        $lastMessage = trim((string)($statusData['message'] ?? $lastMessage));

        if ($status === 'completed') {
            $data = is_array($statusData['result'] ?? null) ? $statusData['result'] : [];
            $analysis = is_array($data['analysis'] ?? null) ? $data['analysis'] : [];
            $summaryText = trim((string)($data['summary'] ?? ''));
            if ($summaryText === '' && !empty($analysis)) {
                $summaryText = meeting_ai_build_summary_text($analysis);
            }

            $transcript = trim((string)($data['transcript'] ?? $transcriptText));
            if ($summaryText === '' || $transcript === '') {
                return [
                    'attempted' => true,
                    'success' => false,
                    'message' => 'AI worker returned an incomplete meeting summary.',
                ];
            }

            return [
                'attempted' => true,
                'success' => true,
                'summary' => $summaryText,
                'analysis' => $analysis,
                'transcript' => $transcript,
                'transcript_provider' => trim((string)($data['transcript_provider'] ?? 'local-worker')),
                'transcript_model' => trim((string)($data['transcript_model'] ?? 'faster-whisper')),
                'summary_provider' => trim((string)($data['summary_provider'] ?? 'local-worker')),
                'summary_model' => trim((string)($data['summary_model'] ?? 'ollama')),
            ];
        }

        if ($status === 'failed') {
            return [
                'attempted' => true,
                'success' => false,
                'message' => $lastMessage !== '' ? $lastMessage : 'AI worker job failed.',
            ];
        }
    }

    return [
        'attempted' => true,
        'success' => false,
        'message' => $lastMessage !== '' ? $lastMessage : 'Local AI worker did not finish within the configured timeout.',
    ];
}

function meeting_ai_build_worker_summary_payload(array $meeting, $existingTranscript = '') {
    $audioPath = trim((string)($meeting['audio_path'] ?? $meeting['audio_file_path'] ?? ''));
    $audioUrl = meeting_ai_public_audio_url($audioPath);
    $transcriptText = trim((string)$existingTranscript);
    $descriptionText = trim((string)($meeting['description'] ?? ''));

    if ($transcriptText === '' && $audioUrl === '' && $descriptionText !== '') {
        $transcriptText = $descriptionText;
    }

    if ($audioUrl === '' && $transcriptText === '') {
        return null;
    }

    return [
        'meeting_id' => (int)($meeting['id'] ?? 0),
        'topic' => trim((string)($meeting['topic'] ?? '')),
        'department' => trim((string)($meeting['department'] ?? '')),
        'description' => $descriptionText,
        'audio_url' => $audioUrl,
        'transcript_text' => $transcriptText,
        'language' => 'km',
    ];
}

function meeting_ai_start_worker_summary_job(array $meeting, $existingTranscript = '') {
    $worker = meeting_ai_get_worker_config();
    if (empty($worker['enabled'])) {
        return [
            'attempted' => false,
            'success' => false,
            'message' => '',
        ];
    }

    $payload = meeting_ai_build_worker_summary_payload($meeting, $existingTranscript);
    if (!is_array($payload)) {
        return [
            'attempted' => false,
            'success' => false,
            'message' => '',
        ];
    }

    $headers = [];
    if ($worker['token'] !== '') {
        $headers[] = 'Authorization: Bearer ' . $worker['token'];
    }

    $response = meeting_ai_http_post_json(
        $worker['url'] . '/summarize-meeting-async',
        $payload,
        $headers,
        min(60, max(20, (int)$worker['timeout']))
    );

    if (!$response['ok']) {
        return [
            'attempted' => true,
            'success' => false,
            'message' => (string)($response['message'] ?? 'AI worker request failed.'),
        ];
    }

    $data = is_array($response['data'] ?? null) ? $response['data'] : [];
    $jobId = trim((string)($data['job_id'] ?? ''));
    if ($jobId === '') {
        return [
            'attempted' => true,
            'success' => false,
            'message' => 'AI worker did not return a job ID.',
        ];
    }

    return [
        'attempted' => true,
        'success' => true,
        'processing' => true,
        'job_id' => $jobId,
        'job_status' => trim((string)($data['status'] ?? 'queued')),
        'message' => trim((string)($data['message'] ?? 'Meeting summary job started.')),
    ];
}

function meeting_ai_get_worker_job_status($jobId) {
    $jobId = trim((string)$jobId);
    if ($jobId === '') {
        return [
            'attempted' => false,
            'success' => false,
            'message' => 'Worker job ID is missing.',
        ];
    }

    $worker = meeting_ai_get_worker_config();
    if (empty($worker['enabled'])) {
        return [
            'attempted' => false,
            'success' => false,
            'message' => 'AI worker is not configured.',
        ];
    }

    $headers = [];
    if ($worker['token'] !== '') {
        $headers[] = 'Authorization: Bearer ' . $worker['token'];
    }

    $response = meeting_ai_http_get_json(
        $worker['url'] . '/jobs/' . rawurlencode($jobId),
        $headers,
        30
    );

    if (!$response['ok']) {
        return [
            'attempted' => true,
            'success' => false,
            'message' => (string)($response['message'] ?? 'AI worker job status check failed.'),
            'status_code' => (int)($response['status'] ?? 0),
        ];
    }

    $data = is_array($response['data'] ?? null) ? $response['data'] : [];
    $status = strtolower(trim((string)($data['status'] ?? 'queued')));
    $message = trim((string)($data['message'] ?? ''));

    if (in_array($status, ['queued', 'running'], true)) {
        return [
            'attempted' => true,
            'success' => true,
            'processing' => true,
            'job_status' => $status,
            'message' => $message !== '' ? $message : 'Local AI worker is still processing this meeting.',
        ];
    }

    if ($status === 'failed') {
        return [
            'attempted' => true,
            'success' => false,
            'job_status' => $status,
            'message' => $message !== '' ? $message : 'AI worker job failed.',
            'status_code' => (int)($data['status_code'] ?? 500),
        ];
    }

    $result = is_array($data['result'] ?? null) ? $data['result'] : [];
    $analysis = is_array($result['analysis'] ?? null) ? $result['analysis'] : [];
    $summaryText = trim((string)($result['summary'] ?? ''));
    if ($summaryText === '' && !empty($analysis)) {
        $summaryText = meeting_ai_build_summary_text($analysis);
    }
    $transcript = trim((string)($result['transcript'] ?? ''));

    if ($status !== 'completed' || $summaryText === '' || $transcript === '') {
        return [
            'attempted' => true,
            'success' => false,
            'job_status' => $status,
            'message' => 'AI worker returned an incomplete meeting summary.',
        ];
    }

    return [
        'attempted' => true,
        'success' => true,
        'processing' => false,
        'job_status' => $status,
        'message' => $message,
        'summary' => $summaryText,
        'analysis' => $analysis,
        'transcript' => $transcript,
        'transcript_provider' => trim((string)($result['transcript_provider'] ?? 'local-worker')),
        'transcript_model' => trim((string)($result['transcript_model'] ?? 'faster-whisper')),
        'summary_provider' => trim((string)($result['summary_provider'] ?? 'local-worker')),
        'summary_model' => trim((string)($result['summary_model'] ?? 'ollama')),
    ];
}

function meeting_ai_update_meeting_job_state($mysqli, $meetingId, $jobId, $jobStatus, $jobMessage = '') {
    $stmt = $mysqli->prepare("UPDATE meetings
        SET summary_job_id = ?,
            summary_job_status = ?,
            summary_job_message = ?,
            summary_job_updated_at = NOW()
        WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param("sssi", $jobId, $jobStatus, $jobMessage, $meetingId);
        $stmt->execute();
        $stmt->close();
    }
}

function meeting_ai_reset_meeting_summary_state($mysqli, $meetingId) {
    $stmt = $mysqli->prepare("UPDATE meetings
        SET transcript_text = '',
            transcript_provider = NULL,
            transcript_model = NULL,
            summary = '',
            summary_json = NULL,
            summary_generated_at = NULL,
            summary_provider = NULL,
            summary_model = NULL,
            summary_job_id = NULL,
            summary_job_status = NULL,
            summary_job_message = NULL,
            summary_job_updated_at = NOW()
        WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param("i", $meetingId);
        $stmt->execute();
        $stmt->close();
    }
}

function meeting_ai_store_completed_summary($mysqli, $meetingId, array $result) {
    $summaryText = trim((string)($result['summary'] ?? ''));
    $transcriptText = trim((string)($result['transcript'] ?? ''));
    $analysis = is_array($result['analysis'] ?? null) ? $result['analysis'] : [];
    $summaryJson = json_encode($analysis, JSON_UNESCAPED_UNICODE);
    $transcriptProvider = trim((string)($result['transcript_provider'] ?? 'local-worker'));
    $transcriptModel = trim((string)($result['transcript_model'] ?? 'faster-whisper'));
    $summaryProvider = trim((string)($result['summary_provider'] ?? 'local-worker'));
    $summaryModel = trim((string)($result['summary_model'] ?? 'ollama'));

    $stmt = $mysqli->prepare("UPDATE meetings
        SET transcript_text = ?,
            transcript_provider = ?,
            transcript_model = ?,
            summary = ?,
            summary_json = ?,
            summary_generated_at = NOW(),
            summary_provider = ?,
            summary_model = ?,
            summary_job_status = 'completed',
            summary_job_message = '',
            summary_job_updated_at = NOW()
        WHERE id = ?");
    if ($stmt) {
        $stmt->bind_param(
            "sssssssi",
            $transcriptText,
            $transcriptProvider,
            $transcriptModel,
            $summaryText,
            $summaryJson,
            $summaryProvider,
            $summaryModel,
            $meetingId
        );
        $stmt->execute();
        $stmt->close();
    }

    return [
        'summary' => $summaryText,
        'transcript' => $transcriptText,
        'analysis' => $analysis,
        'transcript_provider' => $transcriptProvider,
        'transcript_model' => $transcriptModel,
        'summary_provider' => $summaryProvider,
        'summary_model' => $summaryModel,
    ];
}

function meeting_ai_resolve_transcription_provider_config($preferredProvider = null) {
    $preferredProvider = strtolower(trim((string)$preferredProvider));
    $groqKey = trim((string)(defined('GROQ_API_KEY') ? GROQ_API_KEY : ''));
    $openAiKey = trim((string)(defined('OPENAI_API_KEY') ? OPENAI_API_KEY : ''));

    $providers = [];
    if ($groqKey !== '') {
        $providers['groq'] = [
            'provider' => 'groq',
            'endpoint' => 'https://api.groq.com/openai/v1/audio/transcriptions',
            'api_key' => $groqKey,
            'model' => 'whisper-large-v3',
            'max_bytes_hard' => 100 * 1024 * 1024,
            'max_bytes_soft' => 25 * 1024 * 1024,
        ];
    }
    if ($openAiKey !== '') {
        $providers['openai'] = [
            'provider' => 'openai',
            'endpoint' => 'https://api.openai.com/v1/audio/transcriptions',
            'api_key' => $openAiKey,
            'model' => 'gpt-4o-mini-transcribe',
            'max_bytes_hard' => 25 * 1024 * 1024,
            'max_bytes_soft' => 25 * 1024 * 1024,
        ];
    }

    if ($preferredProvider !== '' && isset($providers[$preferredProvider])) {
        return $providers[$preferredProvider];
    }
    if (isset($providers['groq'])) {
        return $providers['groq'];
    }
    if (isset($providers['openai'])) {
        return $providers['openai'];
    }

    return null;
}

function meeting_ai_resolve_transcription_fallback_config(array $currentConfig) {
    $provider = strtolower(trim((string)($currentConfig['provider'] ?? '')));
    if ($provider === 'groq') {
        return meeting_ai_resolve_transcription_provider_config('openai');
    }
    if ($provider === 'openai') {
        return meeting_ai_resolve_transcription_provider_config('groq');
    }
    return null;
}

function meeting_ai_format_bytes($bytes) {
    $bytes = (int)$bytes;
    if ($bytes <= 0) {
        return '0 B';
    }

    $units = ['B', 'KB', 'MB', 'GB'];
    $power = (int)floor(log($bytes, 1024));
    $power = max(0, min($power, count($units) - 1));
    $value = $bytes / pow(1024, $power);
    return number_format($value, $power === 0 ? 0 : 1) . ' ' . $units[$power];
}

function meeting_ai_build_file_too_large_message(array $config, $fileSizeBytes, $statusCode = 413) {
    $provider = strtolower(trim((string)($config['provider'] ?? '')));
    $sizeText = meeting_ai_format_bytes($fileSizeBytes);
    $hardLimit = (int)($config['max_bytes_hard'] ?? 0);
    $softLimit = (int)($config['max_bytes_soft'] ?? 0);

    if ($provider === 'groq') {
        if ($fileSizeBytes > $hardLimit && $hardLimit > 0) {
            return "ឯកសារសំឡេងធំពេកសម្រាប់ការបម្លែងអក្សរ។ ឯកសារនេះមានទំហំ {$sizeText} ខណៈដែល Groq អនុញ្ញាតអតិបរមាប្រហែល " . meeting_ai_format_bytes($hardLimit) . " ក្នុងមួយ request។ សូមបង្រួមជា MP3/M4A ឬបំបែកសំឡេងជាផ្នែកតូចៗសិន។";
        }
        return "ឯកសារសំឡេងនេះធំពេកសម្រាប់ Groq plan បច្ចុប្បន្ន។ ឯកសារនេះមានទំហំ {$sizeText}។ Groq speech-to-text តាម docs អាចមាន soft limit ប្រហែល " . meeting_ai_format_bytes($softLimit) . " សម្រាប់ free tier និងអាចដល់ " . meeting_ai_format_bytes($hardLimit) . " សម្រាប់ dev tier។ សូមបង្រួមឯកសារ ឬបំបែក audio ជាផ្នែកតូចៗ។";
    }

    if ($provider === 'openai') {
        return "ឯកសារសំឡេងធំពេកសម្រាប់ OpenAI transcription API។ ឯកសារនេះមានទំហំ {$sizeText} ខណៈដែល OpenAI អនុញ្ញាតអតិបរមា " . meeting_ai_format_bytes($hardLimit) . " ក្នុងមួយ request។ សូមបង្រួមជា MP3/M4A ឬបំបែកសំឡេងជាផ្នែកតូចៗ។";
    }

    return "ឯកសារសំឡេងធំពេកសម្រាប់ការសង្ខេបដោយ AI (HTTP {$statusCode})។ សូមបង្រួមឯកសារ ឬបំបែកសំឡេងជាផ្នែកតូចៗ។";
}

function meeting_ai_resolve_audio_path($audioPath) {
    $audioPath = trim((string)$audioPath);
    if ($audioPath === '') {
        return [
            'ok' => false,
            'message' => 'No audio file attached.',
        ];
    }

    if (preg_match('#^https?://#i', $audioPath)) {
        $tempPath = tempnam(sys_get_temp_dir(), 'meeting_audio_');
        $content = @file_get_contents($audioPath);
        if ($content === false || $content === '') {
            @unlink($tempPath);
            return [
                'ok' => false,
                'message' => 'Unable to download remote audio file.',
            ];
        }
        file_put_contents($tempPath, $content);
        return [
            'ok' => true,
            'path' => $tempPath,
            'cleanup' => true,
        ];
    }

    $cleanPath = ltrim($audioPath, '/\\');
    $fullPath = __DIR__ . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $cleanPath);
    if (!is_file($fullPath)) {
        $fallbackUrl = "https://app.vvc.asia/flutter/" . ltrim($audioPath, '/\\');
        $tempPath = tempnam(sys_get_temp_dir(), 'meeting_audio_');
        $content = @file_get_contents($fallbackUrl);
        if ($content !== false && $content !== '') {
            file_put_contents($tempPath, $content);
            return [
                'ok' => true,
                'path' => $tempPath,
                'cleanup' => true,
            ];
        }
        @unlink($tempPath);
        return [
            'ok' => false,
            'message' => 'Meeting audio file not found on server.',
        ];
    }

    return [
        'ok' => true,
        'path' => $fullPath,
        'cleanup' => false,
    ];
}

function meeting_ai_public_audio_url($audioPath) {
    $audioPath = trim((string)$audioPath);
    if ($audioPath === '') {
        return '';
    }

    if (preg_match('#^https?://#i', $audioPath)) {
        return $audioPath;
    }

    return "https://app.vvc.asia/flutter/" . ltrim($audioPath, '/\\');
}

function meeting_ai_get_ffmpeg_binary() {
    if (function_exists('resolve_ffmpeg_binary_path')) {
        $resolved = trim((string) resolve_ffmpeg_binary_path());
        if ($resolved !== '') {
            return $resolved;
        }
    }

    $configured = trim((string)(getenv('FFMPEG_BINARY') ?: ''));
    if ($configured !== '') {
        return $configured;
    }

    return 'ffmpeg';
}

function meeting_ai_compact_error_text($raw, $limit = 220) {
    $raw = trim((string)$raw);
    if ($raw === '') {
        return '';
    }

    $clean = strip_tags($raw);
    $clean = preg_replace('/\s+/u', ' ', $clean);
    $clean = trim((string)$clean);
    if ($clean === '') {
        return '';
    }

    if (function_exists('mb_substr')) {
        if (mb_strlen($clean) > $limit) {
            return mb_substr($clean, 0, $limit) . '...';
        }
        return $clean;
    }

    if (strlen($clean) > $limit) {
        return substr($clean, 0, $limit) . '...';
    }
    return $clean;
}

function meeting_ai_build_invalid_transcription_response_message($raw, $statusCode = 0) {
    $snippet = meeting_ai_compact_error_text($raw);
    if ($snippet === '') {
        return $statusCode > 0
            ? 'Transcription service returned an empty response (HTTP ' . $statusCode . ').'
            : 'Transcription service returned an empty response.';
    }

    if (stripos($snippet, 'is a directory') !== false) {
        return 'FFMPEG_BINARY is pointing to a directory, not the ffmpeg binary file. ' . $snippet;
    }

    if (preg_match('/<(html|!doctype)/i', (string)$raw)) {
        return $statusCode > 0
            ? 'Transcription service returned HTML instead of JSON (HTTP ' . $statusCode . '). ' . $snippet
            : 'Transcription service returned HTML instead of JSON. ' . $snippet;
    }

    return $statusCode > 0
        ? 'Transcription service returned an unreadable response (HTTP ' . $statusCode . '). ' . $snippet
        : 'Transcription service returned an unreadable response. ' . $snippet;
}

function meeting_ai_is_transcription_rate_limited($statusCode, array $decoded = null, $raw = '') {
    if ((int)$statusCode === 429) {
        return true;
    }

    $message = '';
    if (is_array($decoded)) {
        $message = (string)($decoded['error']['message'] ?? $decoded['message'] ?? '');
    }
    if ($message === '') {
        $message = (string)$raw;
    }
    $message = strtolower(trim($message));
    if ($message === '') {
        return false;
    }

    return strpos($message, 'rate limit') !== false
        || strpos($message, 'too many requests') !== false
        || strpos($message, 'try again in') !== false
        || strpos($message, 'service tier') !== false;
}

function meeting_ai_transcode_audio_for_asr($inputPath, $targetMaxBytes = 0) {
    if (!is_file($inputPath)) {
        return [
            'success' => false,
            'message' => 'Audio file not found for compression.',
        ];
    }

    $binary = meeting_ai_get_ffmpeg_binary();
    if (!function_exists('shell_exec') || (function_exists('is_php_function_disabled') && is_php_function_disabled('shell_exec'))) {
        return [
            'success' => false,
            'message' => 'Audio compression failed because shell_exec is disabled on the server.',
        ];
    }

    if (function_exists('resolve_ffmpeg_binary_status')) {
        $ffmpegStatus = resolve_ffmpeg_binary_status();
        if (!empty($ffmpegStatus['wrong_platform_binary'])) {
            return [
                'success' => false,
                'message' => 'Audio compression failed because the server is using a Windows ffmpeg.exe file. Please upload the Linux ffmpeg binary instead.',
            ];
        }
        if (empty($ffmpegStatus['resolved_path']) || empty($ffmpegStatus['executable'])) {
            return [
                'success' => false,
                'message' => 'Audio compression failed because FFmpeg is not executable on the server yet.',
            ];
        }
    }

    $tempOutput = tempnam(sys_get_temp_dir(), 'meeting_asr_');
    if ($tempOutput === false) {
        return [
            'success' => false,
            'message' => 'Unable to create temporary file for audio compression.',
        ];
    }
    @unlink($tempOutput);
    $bitrateOptions = ['16k', '12k', '8k'];
    $lastMessage = 'Audio compression failed.';
    $lastSize = 0;

    foreach ($bitrateOptions as $bitrate) {
        $outputPath = $tempOutput . '_' . preg_replace('/[^0-9a-z]/i', '', $bitrate) . '.mp3';
        @unlink($outputPath);

        $cmd = escapeshellarg($binary)
            . ' -y -i ' . escapeshellarg($inputPath)
            . ' -vn -map 0:a:0 -ac 1 -ar 16000 -c:a libmp3lame -b:a ' . escapeshellarg($bitrate) . ' '
            . escapeshellarg($outputPath)
            . ' 2>&1';

        $output = @shell_exec($cmd);
        if (!is_file($outputPath) || @filesize($outputPath) === 0) {
            @unlink($outputPath);
            $lastMessage = 'Audio compression failed. ' . meeting_ai_compact_error_text($output);
            continue;
        }

        $compressedSize = (int)@filesize($outputPath);
        $lastSize = $compressedSize;
        if ($targetMaxBytes > 0 && $compressedSize > $targetMaxBytes) {
            @unlink($outputPath);
            $lastMessage = 'Compressed audio is still too large (' . meeting_ai_format_bytes($compressedSize) . ') after auto-compress at ' . $bitrate . '.';
            continue;
        }

        return [
            'success' => true,
            'path' => $outputPath,
            'size_bytes' => $compressedSize,
            'cleanup' => true,
        ];
    }

    if ($targetMaxBytes > 0 && $lastSize > 0) {
        return [
            'success' => false,
            'message' => $lastMessage,
        ];
    }

    return [
        'success' => false,
        'message' => $lastMessage,
    ];
}

function meeting_ai_transcribe_audio_file($audioFilePath, array $meeting = [], $configOverride = null, array $attemptedProviders = []) {
    $config = is_array($configOverride) ? $configOverride : meeting_ai_resolve_transcription_provider_config();
    if (!$config) {
        return [
            'success' => false,
            'message' => 'Audio transcription provider is not configured.',
        ];
    }

    $originalAudioFilePath = $audioFilePath;
    $fileSizeBytes = is_file($audioFilePath) ? (int)@filesize($audioFilePath) : 0;
    $provider = strtolower(trim((string)($config['provider'] ?? '')));
    if ($provider !== '') {
        $attemptedProviders[] = $provider;
        $attemptedProviders = array_values(array_unique($attemptedProviders));
    }
    $hardLimit = (int)($config['max_bytes_hard'] ?? 0);
    $softLimit = (int)($config['max_bytes_soft'] ?? 0);
    $uploadLimit = $hardLimit;
    if ($provider === 'groq' && $softLimit > 0) {
        $uploadLimit = $softLimit;
    }
    $compressionTarget = $uploadLimit;
    if ($compressionTarget > (1024 * 1024)) {
        $compressionTarget -= (1024 * 1024);
    }
    $audioPath = trim((string)($meeting['audio_path'] ?? $meeting['audio_file_path'] ?? ''));
    $publicUrl = meeting_ai_public_audio_url($audioPath);
    $cleanupLocalPath = false;

    if ($provider === 'groq' && $publicUrl !== '' && ($fileSizeBytes <= 0 || ($uploadLimit > 0 && $fileSizeBytes > $uploadLimit))) {
        $ch = curl_init($config['endpoint']);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, [
            'Authorization: Bearer ' . $config['api_key'],
        ]);
        curl_setopt($ch, CURLOPT_POSTFIELDS, [
            'url' => $publicUrl,
            'model' => $config['model'],
            'language' => 'km',
            'response_format' => 'json',
        ]);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
        curl_setopt($ch, CURLOPT_TIMEOUT, 180);

        $raw = curl_exec($ch);
        $error = curl_error($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($raw !== false && $error === '') {
            $decoded = json_decode($raw, true);
            if (meeting_ai_is_transcription_rate_limited($status, is_array($decoded) ? $decoded : null, $raw)) {
                $fallbackConfig = meeting_ai_resolve_transcription_fallback_config($config);
                $fallbackProvider = strtolower(trim((string)($fallbackConfig['provider'] ?? '')));
                if ($fallbackConfig && $fallbackProvider !== '' && !in_array($fallbackProvider, $attemptedProviders, true)) {
                    return meeting_ai_transcribe_audio_file($originalAudioFilePath, $meeting, $fallbackConfig, $attemptedProviders);
                }
            }
            if (is_array($decoded) && $status < 400) {
                $transcript = trim((string)($decoded['text'] ?? ''));
                if ($transcript !== '') {
                    return [
                        'success' => true,
                        'provider' => $config['provider'],
                        'model' => $config['model'],
                        'text' => $transcript,
                    ];
                }
            }
        }
    }

    if ($provider === 'openai' && $hardLimit > 0 && $fileSizeBytes > $hardLimit) {
        $compressed = meeting_ai_transcode_audio_for_asr($audioFilePath, $compressionTarget);
        if ($compressed['success']) {
            $audioFilePath = $compressed['path'];
            $fileSizeBytes = (int)($compressed['size_bytes'] ?? @filesize($audioFilePath));
            $cleanupLocalPath = !empty($compressed['cleanup']);
        } else {
            return [
                'success' => false,
                'message' => (string)($compressed['message'] ?? meeting_ai_build_file_too_large_message($config, $fileSizeBytes, 413)),
            ];
        }
    }

    if ($provider === 'groq' && $uploadLimit > 0 && $fileSizeBytes > $uploadLimit) {
        $compressed = meeting_ai_transcode_audio_for_asr($audioFilePath, $compressionTarget);
        if ($compressed['success']) {
            $audioFilePath = $compressed['path'];
            $fileSizeBytes = (int)($compressed['size_bytes'] ?? @filesize($audioFilePath));
            $cleanupLocalPath = !empty($compressed['cleanup']);
        } else {
            return [
                'success' => false,
                'message' => (string)($compressed['message'] ?? meeting_ai_build_file_too_large_message($config, $fileSizeBytes, 413)),
            ];
        }
    }

    $ch = curl_init($config['endpoint']);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $config['api_key'],
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'file' => new CURLFile($audioFilePath),
        'model' => $config['model'],
        'language' => 'km',
        'response_format' => 'json',
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 15);
    curl_setopt($ch, CURLOPT_TIMEOUT, 180);

    $raw = curl_exec($ch);
    $error = curl_error($ch);
    $status = (int)curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    if ($cleanupLocalPath && is_file($audioFilePath)) {
        @unlink($audioFilePath);
    }

    $decoded = json_decode((string)$raw, true);
    if (meeting_ai_is_transcription_rate_limited($status, is_array($decoded) ? $decoded : null, $raw)) {
        $fallbackConfig = meeting_ai_resolve_transcription_fallback_config($config);
        $fallbackProvider = strtolower(trim((string)($fallbackConfig['provider'] ?? '')));
        if ($fallbackConfig && $fallbackProvider !== '' && !in_array($fallbackProvider, $attemptedProviders, true)) {
            return meeting_ai_transcribe_audio_file($originalAudioFilePath, $meeting, $fallbackConfig, $attemptedProviders);
        }
    }

    if ($raw === false || $error !== '') {
        return [
            'success' => false,
            'message' => $error !== '' ? $error : 'Transcription request failed.',
        ];
    }

    if (!is_array($decoded)) {
        if (is_string($decoded) && trim($decoded) !== '') {
            return [
                'success' => true,
                'provider' => $config['provider'],
                'model' => $config['model'],
                'text' => trim($decoded),
            ];
        }
        return [
            'success' => false,
            'message' => meeting_ai_build_invalid_transcription_response_message($raw, $status),
        ];
    }

    if ($status >= 400) {
        if ($status === 413) {
            return [
                'success' => false,
                'message' => meeting_ai_build_file_too_large_message($config, $fileSizeBytes, $status),
            ];
        }
        return [
            'success' => false,
            'message' => (string)($decoded['error']['message'] ?? ('HTTP ' . $status)),
        ];
    }

    $transcript = trim((string)($decoded['text'] ?? ''));
    if ($transcript === '') {
        return [
            'success' => false,
            'message' => 'Transcription result was empty.',
        ];
    }

    return [
        'success' => true,
        'provider' => $config['provider'],
        'model' => $config['model'],
        'text' => $transcript,
    ];
}

function meeting_ai_generate_summary_payload(array $meeting, $transcriptText) {
    $summaryProvider = ai_chat_resolve_provider_config();
    if (!$summaryProvider) {
        return [
            'success' => false,
            'message' => 'AI summary provider is not configured.',
        ];
    }

    $topic = trim((string)($meeting['topic'] ?? ''));
    $department = trim((string)($meeting['department'] ?? ''));
    $description = trim((string)($meeting['description'] ?? ''));

    $prompt = "អ្នកជាជំនួយការសរសេររបាយការណ៍កិច្ចប្រជុំជាភាសាខ្មែរ។ សូមអាន transcript ខាងក្រោម ហើយត្រឡប់តែ JSON មួយ object ប៉ុណ្ណោះ ដោយមាន key ទាំងនេះជាច្បាស់៖ headline, overview, key_points, decisions, action_items, next_steps, keywords។\n\n"
        . "លក្ខខណ្ឌ:\n"
        . "- សរសេរទាំងអស់ជាភាសាខ្មែរ\n"
        . "- key_points, decisions, action_items, next_steps, keywords ត្រូវជា array នៃ string\n"
        . "- overview ខ្លី តែច្បាស់\n"
        . "- ប្រសិនបើមិនមានទិន្នន័យ សូមប្រើ string ទទេ ឬ array ទទេ\n"
        . "- កុំដាក់ markdown fence ឬអត្ថបទបន្ថែមក្រៅ JSON\n\n"
        . "ប្រធានបទ: " . ($topic !== '' ? $topic : 'មិនបានបញ្ជាក់') . "\n"
        . "ផ្នែក/ក្រុម: " . ($department !== '' ? $department : 'មិនបានបញ្ជាក់') . "\n"
        . "Context: " . ($description !== '' ? $description : 'មិនមាន') . "\n\n"
        . "Transcript:\n" . trim((string)$transcriptText);

    $response = ai_chat_http_post_json(
        $summaryProvider['endpoint'],
        [
            'model' => $summaryProvider['model'],
            'messages' => [
                [
                    'role' => 'system',
                    'content' => 'You create structured meeting notes in Khmer and return valid JSON only.',
                ],
                [
                    'role' => 'user',
                    'content' => $prompt,
                ],
            ],
            'temperature' => 0.2,
        ],
        ['Authorization: Bearer ' . $summaryProvider['api_key']]
    );

    if (!$response['ok']) {
        return [
            'success' => false,
            'message' => (string)($response['message'] ?? 'Summary request failed.'),
        ];
    }

    $assistantText = trim((string)($response['data']['choices'][0]['message']['content'] ?? ''));
    $analysis = meeting_ai_parse_summary_payload($assistantText);
    $summaryText = meeting_ai_build_summary_text($analysis);

    return [
        'success' => true,
        'provider' => $summaryProvider['provider'],
        'model' => $summaryProvider['model'],
        'analysis' => $analysis,
        'summary' => $summaryText,
    ];
}

// Initialize tables
ensure_api_notification_tables($mysqli);
ensure_app_scan_settings_table($mysqli);
ensure_daily_report_telegram_table($mysqli);
ensure_daily_reports_table($mysqli);
ensure_mission_letters_table($mysqli);
ensure_meetings_table($mysqli);
ensure_ai_chat_tables($mysqli);
ensure_trip_tables($mysqli);
ensure_work_checklist_table($mysqli);

function ensure_work_checklist_table($mysqli) {
    $mysqli->query("CREATE TABLE IF NOT EXISTS work_checklist (
        id INT AUTO_INCREMENT PRIMARY KEY,
        admin_id VARCHAR(64) NOT NULL,
        user_id VARCHAR(64) DEFAULT NULL,
        task TEXT NOT NULL,
        category VARCHAR(100) DEFAULT 'General',
        is_done TINYINT(1) DEFAULT 0,
        image_path VARCHAR(255) DEFAULT NULL,
        start_date DATE DEFAULT NULL,
        start_time VARCHAR(10) DEFAULT NULL,
        end_date DATE DEFAULT NULL,
        end_time VARCHAR(10) DEFAULT NULL,
        reminder_at DATETIME DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_admin (admin_id),
        KEY idx_user (user_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    $cols = []; $res = $mysqli->query("SHOW COLUMNS FROM work_checklist");
    if($res){
        while($r = $res->fetch_assoc()){ $cols[] = $r['Field']; }
        $res->close();
    }

    $missing = [
        'category' => "VARCHAR(100) DEFAULT 'General' AFTER task",
        'image_path' => 'VARCHAR(255) DEFAULT NULL',
        'start_date' => 'DATE DEFAULT NULL',
        'start_time' => 'VARCHAR(10) DEFAULT NULL',
        'end_date' => 'DATE DEFAULT NULL',
        'end_time' => 'VARCHAR(10) DEFAULT NULL',
        'reminder_at' => 'DATETIME DEFAULT NULL',
        'user_id' => 'VARCHAR(64) DEFAULT NULL AFTER admin_id'
    ];

    foreach($missing as $col => $type) {
        if(!in_array($col, $cols)) {
            $mysqli->query("ALTER TABLE work_checklist ADD COLUMN $col $type");
        }
    }
}

function ensure_trip_tables($mysqli) {
    // 1. employee_trips table
    $mysqli->query("CREATE TABLE IF NOT EXISTS employee_trips (
        id INT AUTO_INCREMENT PRIMARY KEY,
        employee_id VARCHAR(64) NOT NULL,
        employee_name VARCHAR(255) DEFAULT NULL,
        customer_id INT DEFAULT 0,
        customer_name VARCHAR(255) DEFAULT NULL,
        start_lat DOUBLE DEFAULT 0,
        start_lng DOUBLE DEFAULT 0,
        end_lat DOUBLE DEFAULT 0,
        end_lng DOUBLE DEFAULT 0,
        total_distance_km DOUBLE DEFAULT 0,
        duration_minutes INT DEFAULT 0,
        status VARCHAR(20) DEFAULT 'active',
        started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        ended_at TIMESTAMP NULL DEFAULT NULL,
        KEY idx_eid (employee_id),
        KEY idx_status (status)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 2. trip_locations table
    $mysqli->query("CREATE TABLE IF NOT EXISTS trip_locations (
        id INT AUTO_INCREMENT PRIMARY KEY,
        trip_id INT NOT NULL,
        latitude DOUBLE NOT NULL,
        longitude DOUBLE NOT NULL,
        speed DOUBLE DEFAULT 0,
        accuracy DOUBLE DEFAULT 0,
        recorded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        KEY idx_trip_id (trip_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // 3. tracking_customers table
    $mysqli->query("CREATE TABLE IF NOT EXISTS tracking_customers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        latitude DOUBLE NOT NULL,
        longitude DOUBLE NOT NULL,
        address TEXT DEFAULT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

    // Fix existing tables collation if they were created with unicode_ci previously
    $mysqli->query("ALTER TABLE employee_trips CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $mysqli->query("ALTER TABLE trip_locations CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
    $mysqli->query("ALTER TABLE tracking_customers CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
}

// Ensure checkin_logs has photo_path
$check_photo = $mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'photo_path'");
if ($check_photo && $check_photo->num_rows === 0) {
    $mysqli->query("ALTER TABLE checkin_logs ADD COLUMN photo_path VARCHAR(255) DEFAULT NULL");
}

// Ensure checkin_logs has employee_name so report can show name even when users join fails
$check_emp_name = $mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'employee_name'");
if ($check_emp_name && $check_emp_name->num_rows === 0) {
    $mysqli->query("ALTER TABLE checkin_logs ADD COLUMN employee_name VARCHAR(255) DEFAULT NULL AFTER employee_id");
}

// Ensure checkin_logs has geo-coordinates
$check_geo = $mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'latitude'");
if ($check_geo && $check_geo->num_rows === 0) {
    $mysqli->query("ALTER TABLE checkin_logs ADD COLUMN latitude DOUBLE DEFAULT NULL, ADD COLUMN longitude DOUBLE DEFAULT NULL");
}

// Ensure checkin_logs has qr_location_id (0 = outside scan)
$check_qr = $mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'qr_location_id'");
if ($check_qr && $check_qr->num_rows === 0) {
    $mysqli->query("ALTER TABLE checkin_logs ADD COLUMN qr_location_id INT DEFAULT 0");
}

// Ensure checkin_logs has geo_address
$check_addr = $mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'geo_address'");
if ($check_addr && $check_addr->num_rows === 0) {
    $mysqli->query("ALTER TABLE checkin_logs ADD COLUMN geo_address TEXT DEFAULT NULL");
}

// ===== FACE REGISTRATION TABLE =====
// បង្កើតតារាងដើម្បីរក្សាទុករូបថតចុះឈ្មោះ Face ID
$mysqli->query("CREATE TABLE IF NOT EXISTS employee_face_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id VARCHAR(64) NOT NULL,
    photo_path VARCHAR(512) NOT NULL,
    photo_index TINYINT DEFAULT 0 COMMENT '0=straight,1=left,2=right',
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    registered_by VARCHAR(64) DEFAULT NULL COMMENT 'admin who registered on behalf',
    INDEX idx_face_employee (employee_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

// បន្ថែម face_registered column ក្នុង users table
$check_face_reg = $mysqli->query("SHOW COLUMNS FROM users LIKE 'face_registered'");
if ($check_face_reg && $check_face_reg->num_rows === 0) {
    $mysqli->query("ALTER TABLE users ADD COLUMN face_registered TINYINT(1) DEFAULT 0");
}

function get_address_from_gps($lat, $lon) {
    if (!$lat || !$lon) return null;
    $url = "https://nominatim.openstreetmap.org/reverse?format=json&lat=$lat&lon=$lon&zoom=18&addressdetails=1";
    $options = [
        "http" => [
            "header" => "User-Agent: VvcAttendanceApp/1.0\r\n",
            "timeout" => 3
        ]
    ];
    $context = stream_context_create($options);
    $result = @file_get_contents($url, false, $context);
    if ($result) {
        $data = json_decode($result, true);
        return $data['display_name'] ?? null;
    }
    return null;
}

function haversine_distance($lat1, $lon1, $lat2, $lon2) {
    $lat1 = floatval($lat1); $lon1 = floatval($lon1);
    $lat2 = floatval($lat2); $lon2 = floatval($lon2);
    $dLat = deg2rad($lat2 - $lat1); $dLon = deg2rad($lon2 - $lon1);
    $lat1 = deg2rad($lat1); $lat2 = deg2rad($lat2);
    $a = sin($dLat / 2) * sin($dLat / 2) + sin($dLon / 2) * sin($dLon / 2) * cos($lat1) * cos($lat2);
    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
    return EARTH_RADIUS_KM * $c * 1000;
}

if (!function_exists('is_system_wide_scan_setting_key')) {
    function is_system_wide_scan_setting_key($key) {
        static $global_keys = ['app_latest_version', 'app_latest_build', 'app_apk_url', 'app_update_message', 'app_force_update', 'face_scan_enabled'];
        return in_array((string)$key, $global_keys, true);
    }
}

function get_scan_setting($key, $default = '', $mysqli, $employee_id = null) {
    static $scan_settings_cache = [];

    if (is_system_wide_scan_setting_key($key)) {
        $employee_id = null;
    }

    // Resolve admin_id
    $admin_id = 'SYSTEM_WIDE';
    if ($employee_id) {
        $stmt = $mysqli->prepare("SELECT user_role, COALESCE(created_by_admin_id, '') AS created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param("s", $employee_id);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res && $row = $res->fetch_assoc()) {
                $role    = $row['user_role'] ?? '';
                $creator = $row['created_by_admin_id'] ?? '';

                // Step 1: Does this employee have their own settings row?
                $chk = $mysqli->prepare("SELECT 1 FROM app_scan_settings WHERE admin_id = ? LIMIT 1");
                if ($chk) {
                    $chk->bind_param("s", $employee_id);
                    $chk->execute();
                    $has_own = ($chk->get_result()->num_rows > 0);
                    $chk->close();
                } else {
                    $has_own = false;
                }

                if ($has_own) {
                    $admin_id = $employee_id;
                } elseif (!empty($creator)) {
                    $admin_id = $creator;  // Use creator/manager's settings
                } elseif (strcasecmp($role, 'Admin') === 0) {
                    $admin_id = $employee_id;
                }
                // else: remains 'SYSTEM_WIDE'
            }
            $stmt->close();
        }
    }


    $cache_key = "{$admin_id}_{$key}";
    if (isset($scan_settings_cache[$cache_key])) return $scan_settings_cache[$cache_key];

    // Priority 1: Check admin-specific app_scan_settings (New UI)
    $stmt = $mysqli->prepare("SELECT setting_value FROM app_scan_settings WHERE admin_id = ? AND setting_key = ? LIMIT 1");
    if ($stmt) {
        $stmt->bind_param("ss", $admin_id, $key);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            $val = $row['setting_value'];
            $scan_settings_cache[$cache_key] = $val;
            $stmt->close();
            return $val;
        }
        $stmt->close();
    }

    // Priority 2: Fallback to SYSTEM_WIDE app_scan_settings
    if ($admin_id !== 'SYSTEM_WIDE') {
        $stmt = $mysqli->prepare("SELECT setting_value FROM app_scan_settings WHERE admin_id = 'SYSTEM_WIDE' AND setting_key = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param("s", $key);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($row = $res->fetch_assoc()) {
                $val = $row['setting_value'];
                $scan_settings_cache[$cache_key] = $val;
                $stmt->close();
                return $val;
            }
            $stmt->close();
        }
    }

    // Priority 3: Legacy system_settings (Global overrides)
    $stmt_sys = $mysqli->prepare("SELECT setting_value FROM system_settings WHERE setting_key = ? LIMIT 1");
    if ($stmt_sys) {
        $stmt_sys->bind_param("s", $key);
        $stmt_sys->execute();
        $res_sys = $stmt_sys->get_result();
        if ($res_sys && $row_sys = $res_sys->fetch_assoc()) {
            $val = $row_sys['setting_value'];
            $scan_settings_cache[$cache_key] = $val;
            $stmt_sys->close();
            return $val;
        }
        $stmt_sys->close();
    }

    $scan_settings_cache[$cache_key] = $default;
    return $default;
}

function render_template_strip_empty_lines($template, $replacements) {
    if (empty($template)) return '';
    $rendered = str_replace(array_keys($replacements), array_values($replacements), $template);
    // Normalize double-m distance units (e.g., "15mm" -> "15m", "0mm" -> "0m")
    $rendered = preg_replace('/(\d+)\s*mm\b/iu', '$1m', $rendered);
    // Remove lines that still contain unreplaced placeholders like {{something}}
    // /mu flag ensures it works correctly with Khmer/Unicode text
    $lines = explode("\n", $rendered);
    $filtered = [];
    foreach ($lines as $line) {
        if (!preg_match('/\{\{.*\}\}/u', $line)) {
            $filtered[] = $line;
        }
    }
    return trim(implode("\n", $filtered));
}

function sendAttendanceTelegram($mysqli, $eid, $data = []) {
    $botToken = getTelegramBotToken($mysqli, $eid);
    $chatId = get_scan_setting('telegram_chat_id', TELEGRAM_CHAT_ID, $mysqli, $eid);
    $notifyEnabled = get_scan_setting('telegram_notify_attendance', '1', $mysqli, $eid);

    if (!$botToken || !$chatId || $notifyEnabled != '1') return false;

    // 2. Fetch User Details for mapping
    $stmt = $mysqli->prepare("SELECT department, position FROM users WHERE employee_id = ? LIMIT 1");
    $uDept = 'N/A'; $uPos = 'N/A';
    if ($stmt) {
        $stmt->bind_param("s", $eid);
        $stmt->execute();
        $um = $stmt->get_result()->fetch_assoc();
        if ($um) {
            $uDept = $um['department'] ?: 'N/A';
            $uPos = $um['position'] ?: 'N/A';
        }
        $stmt->close();
    }

    // 2. Fetch Template
    $default_tpl = "<b>Name :</b> {{name}}\n<b>Status :</b> {{action}} ({{status}})\nReason : {{late_reason}}\n------------------------------------------\n<b>ID :</b> {{employee_id}}\n<b>Department :</b> {{field_department}}\n<b>Position :</b> {{field_position}}\n<b>Date/Time :</b> {{time}}\n<b>Area :</b> {{location_name}}\n<b>Distance :</b> {{distance_m}}";
    $template = get_scan_setting('telegram_tpl_attendance', $default_tpl, $mysqli, $eid);

    // 3. Icons Enhancement (Blue/Red circles matching professional look)
    $iconGood = get_scan_setting('status_icon_good', '🔵', $mysqli, $eid);
    $iconLate = get_scan_setting('status_icon_late', '🔴', $mysqli, $eid);

    $statusText = $data['status'] ?? '';
    if (stripos($statusText, 'Good') !== false || stripos($statusText, 'Normal') !== false || stripos($statusText, 'OK') !== false) {
        $statusIcon = $iconGood;
    } else {
        $statusIcon = $iconLate;
    }

    // 4. Time Format
    $timeFmt = get_scan_setting('telegram_time_format', 'd/m/Y h:i:s A', $mysqli, $eid);
    $displayTime = date($timeFmt);

    // 5. Placeholders
    $replacements = [
        '{{name}}' => $data['name'] ?? 'Unknown',
        '{{id}}' => $eid,
        '{{employee_id}}' => $eid,
        '{{dept}}' => $uDept,
        '{{pos}}' => $uPos,
        '{{action}}' => $data['action'] ?? '',
        '{{status}}' => ($data['status'] ?? '') . ($statusIcon ? ' ' . $statusIcon : ''),
        '{{status_icon}}' => $statusIcon,
        '{{time}}' => $displayTime,
        '{{location_name}}' => $data['location_name'] ?? '',
        '{{distance_m}}' => isset($data['distance_m']) ? (round($data['distance_m']) . 'm') : '',
        '{{late_reason}}' => $data['late_reason'] ?? '',
        '{{late_reason_section}}' => (!empty($data['late_reason'])) ? "<b>Reason :</b> " . $data['late_reason'] : '',
        '{{field_department}}' => $uDept,
        '{{field_position}}' => $uPos,
    ];

    // Add custom fields
    $stmt = $mysqli->prepare("SELECT custom_data FROM users WHERE employee_id = ? LIMIT 1");
    if ($stmt) {
        $stmt->bind_param("s", $eid);
        $stmt->execute();
        $res = $stmt->get_result()->fetch_assoc();
        if ($res && !empty($res['custom_data'])) {
            $custom = json_decode($res['custom_data'], true);
            if (is_array($custom)) {
                foreach ($custom as $k => $v) { $replacements["{{field_$k}}"] = (string)$v; }
            }
        }
        $stmt->close();
    }

    $message = render_template_strip_empty_lines($template, $replacements);

    $url = "https://api.telegram.org/bot$botToken/sendMessage";
    $payload = [
        'chat_id' => $chatId,
        'text' => $message,
        'parse_mode' => 'HTML'
    ];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 1);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}

function sendRequestTelegram($mysqli, $eid, $data = []) {
    $botToken = getTelegramBotToken($mysqli, $eid);
    $chatId = get_scan_setting('telegram_chat_id', TELEGRAM_CHAT_ID, $mysqli, $eid);
    $notifyEnabled = get_scan_setting('telegram_notify_requests', '1', $mysqli, $eid);

    if (!$botToken || !$chatId || $notifyEnabled != '1') return false;

    $default_tpl = "<b>[NEW REQUEST]</b>\n<b>ប្រភេទ:</b> {{request_type}}\n<b>អ្នកស្នើ:</b> {{name}}\n<b>សេចក្តីសង្ខេប:</b> {{summary}}\n<b>ម៉ោង:</b> {{time}}";
    $template = get_scan_setting('telegram_tpl_request', $default_tpl, $mysqli, $eid);

    $timeFmt = get_scan_setting('telegram_time_format', 'd-m-Y H:i:s', $mysqli, $eid);

    $replacements = [
        '{{name}}' => $data['name'] ?? 'Unknown',
        '{{employee_id}}' => $eid,
        '{{request_type}}' => $data['request_type'] ?? '',
        '{{summary}}' => $data['summary'] ?? '',
        '{{time}}' => date($timeFmt),
    ];

    $message = render_template_strip_empty_lines($template, $replacements);

    $url = "https://api.telegram.org/bot$botToken/sendMessage";
    $payload = ['chat_id' => $chatId, 'text' => $message, 'parse_mode' => 'HTML'];

    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($payload));
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 1);
    $result = curl_exec($ch);
    curl_close($ch);
    return $result;
}



function apiResponse($data) {
    if (ob_get_length()) ob_clean();
    // Ensure 'success' key is always present for consistency
    if (!isset($data['success'])) {
        $data['success'] = (isset($data['status']) && $data['status'] === 'success');
    }
    $json = json_encode($data, JSON_UNESCAPED_UNICODE);
    if ($json === false) {
        $json = json_encode(['success' => false, 'message' => 'JSON encode error: ' . json_last_error_msg()]);
    }
    echo $json;
    exit;
}

function getBearerToken() {
    $headers = [];
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
    } else {
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$key] = $value;
            }
        }
    }
    $auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    if (stripos($auth, 'Bearer ') === 0) return trim(substr($auth, 7));
    return null;
}

$token = getBearerToken();
$user = null;
if ($token) {
    try {
        $stmt = $mysqli->prepare("SELECT u.id, at.employee_id, u.name, u.user_role, u.system_role, u.position, u.department, u.avatar FROM active_tokens at JOIN users u ON at.employee_id = u.employee_id WHERE at.auth_token = ? LIMIT 1");
        if ($stmt) {
            $stmt->bind_param("s", $token);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result) {
                $user = $result->fetch_assoc();
            } else {
                // Fallback if mysqlnd is missing (get_result() returns null/false)
                $stmt->store_result();
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($u_id, $e_id, $u_name, $u_role, $u_sys_role, $u_pos, $u_dept, $u_avat);
                    $stmt->fetch();
                    $user = [
                        'id' => $u_id,
                        'employee_id' => $e_id,
                        'name' => $u_name,
                        'user_role' => $u_role,
                        'system_role' => $u_sys_role,
                        'position' => $u_pos,
                        'department' => $u_dept,
                        'avatar' => $u_avat
                    ];
                }
            }
            $stmt->close();
            // Update last activity for this session
            if ($user && !empty($token)) {
                $mysqli->query("UPDATE active_tokens SET last_used = NOW() WHERE auth_token = '" . $mysqli->real_escape_string($token) . "'");
            }
        }
    } catch (Exception $e) {}
}

// 4. Action Routing
$actionSource = $_POST['action'] ?? $_GET['action'] ?? $_POST['ajax_action'] ?? $_GET['ajax_action'] ?? '';
$action = strtolower(trim($actionSource));

switch ($action) {
    case 'view_face_log':
        $logPath = __DIR__ . '/uploads/face_match_debug.log';
        if (file_exists($logPath)) {
            $content = file_get_contents($logPath);
            echo json_encode(['success' => true, 'log' => $content]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Log file not found at: ' . $logPath]);
        }
        exit;
    case 'update_fcm_token':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $fcm_token = $_POST['token'] ?? '';
        $platform = $_POST['platform'] ?? (isset($_SERVER['HTTP_USER_AGENT']) && stripos($_SERVER['HTTP_USER_AGENT'], 'Dart') === false ? 'Web' : 'Mobile');
        $eid = $user['employee_id'] ?? '';

        if (empty($fcm_token) || empty($eid)) {
            apiResponse(['success' => false, 'message' => 'Missing token']);
        }

        // 1. Update legacy column in users (single token)
        $stmtUserToken = $mysqli->prepare("UPDATE users SET fcm_token = ? WHERE employee_id = ?");
        if ($stmtUserToken) {
            $stmtUserToken->bind_param("ss", $fcm_token, $eid);
            $stmtUserToken->execute();
            $stmtUserToken->close();
        }

        // 2. Save/Update in user_fcm_tokens (multi-device)
        $stmt = $mysqli->prepare("INSERT INTO user_fcm_tokens (employee_id, fcm_token, platform) VALUES (?, ?, ?)
                                ON DUPLICATE KEY UPDATE employee_id = VALUES(employee_id), platform = VALUES(platform), last_seen = CURRENT_TIMESTAMP");
        if ($stmt) {
            $stmt->bind_param("sss", $eid, $fcm_token, $platform);
            $stmt->execute();
            $stmt->close();
            apiResponse(['success' => true, 'message' => 'FCM Token registered successfully']);
        } else {
            apiResponse(['success' => false, 'message' => 'DB Error']);
        }
        break;

    case 'logout':
        $push_token = trim((string) ($_POST['fcm_token'] ?? ''));
        $session_revoked = false;
        $push_token_removed = false;

        if (!empty($token)) {
            $stmt = $mysqli->prepare("DELETE FROM active_tokens WHERE auth_token = ?");
            if ($stmt) {
                $stmt->bind_param("s", $token);
                $stmt->execute();
                $session_revoked = ($stmt->affected_rows > 0);
                $stmt->close();
            }
        }

        if ($user && $push_token !== '') {
            $eid = (string) ($user['employee_id'] ?? '');
            if ($eid !== '') {
                $stmt = $mysqli->prepare("DELETE FROM user_fcm_tokens WHERE employee_id = ? AND fcm_token = ?");
                if ($stmt) {
                    $stmt->bind_param("ss", $eid, $push_token);
                    $stmt->execute();
                    $push_token_removed = ($stmt->affected_rows > 0);
                    $stmt->close();
                }

                $stmt = $mysqli->prepare("UPDATE users SET fcm_token = NULL WHERE employee_id = ? AND fcm_token = ?");
                if ($stmt) {
                    $stmt->bind_param("ss", $eid, $push_token);
                    $stmt->execute();
                    $push_token_removed = $push_token_removed || ($stmt->affected_rows > 0);
                    $stmt->close();
                }
            }
        }

        apiResponse([
            'success' => true,
            'message' => 'Logged out successfully',
            'session_revoked' => $session_revoked,
            'push_token_removed' => $push_token_removed,
        ]);
        break;

    case 'save_meeting':
        if (!$user) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Unauthorized']);

        $topic = $_POST['topic'] ?? '';
        $department = $_POST['department'] ?? '';
        $date = $_POST['date'] ?? '';
        $description = $_POST['description'] ?? '';
        $external_url = $_POST['external_url'] ?? '';
        $audioOriginalName = trim((string)($_POST['audio_original_name'] ?? ''));

        if (empty($topic)) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Topic is required']);

        // Handle Audio Upload
        $audio_path = '';
        if (isset($_FILES['audio_file']) && $_FILES['audio_file']['error'] === UPLOAD_ERR_OK) {
            $ext = pathinfo($_FILES['audio_file']['name'], PATHINFO_EXTENSION);
            if (empty($ext)) $ext = 'm4a';
            if ($audioOriginalName === '') {
                $audioOriginalName = (string)($_FILES['audio_file']['name'] ?? '');
            }
            $filename = 'meeting_audio_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
            $upload_path = 'uploads/meetings/audio/' . $filename;
            if (!is_dir('uploads/meetings/audio/')) mkdir('uploads/meetings/audio/', 0777, true);
            if (move_uploaded_file($_FILES['audio_file']['tmp_name'], $upload_path)) {
                $audio_path = $upload_path;
            }
        }

        // Handle Photos Upload (Multiple)
        $photos_paths = [];
        $photos_input = $_FILES['related_photos'] ?? ($_FILES['related_photos[]'] ?? null);
        if ($photos_input && isset($photos_input['tmp_name']) && is_array($photos_input['tmp_name'])) {
            if (!is_dir('uploads/meetings/photos/')) mkdir('uploads/meetings/photos/', 0777, true);
            foreach ($photos_input['tmp_name'] as $key => $tmp_name) {
                if (($photos_input['error'][$key] ?? UPLOAD_ERR_NO_FILE) === UPLOAD_ERR_OK) {
                    $ext = pathinfo($photos_input['name'][$key] ?? '', PATHINFO_EXTENSION);
                    $filename = 'meeting_photo_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
                    $upload_path = 'uploads/meetings/photos/' . $filename;
                    if (move_uploaded_file($tmp_name, $upload_path)) {
                        $photos_paths[] = $upload_path;
                    }
                }
            }
        }

        $photos_json = json_encode($photos_paths);
        $eid = $user['employee_id'];

        $stmt = $mysqli->prepare("INSERT INTO meetings (topic, department, meeting_date, description, audio_path, audio_file_path, audio_original_name, external_url, photos, related_photos, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
        if ($stmt) {
            $stmt->bind_param("sssssssssss", $topic, $department, $date, $description, $audio_path, $audio_path, $audioOriginalName, $external_url, $photos_json, $photos_json, $eid);
            if ($stmt->execute()) {
                apiResponse(['success' => true, 'status' => 'success', 'message' => 'Meeting saved successfully']);
            } else {
                apiResponse(['success' => false, 'status' => 'error', 'message' => 'Insert failed: ' . $stmt->error]);
            }
            $stmt->close();
        } else {
            apiResponse(['success' => false, 'status' => 'error', 'message' => 'Prepare failed: ' . $mysqli->error]);
        }
        break;

    case 'get_meetings':
    case 'fetch_meetings':
        $sql = "SELECT *, DATE_FORMAT(meeting_date, '%d/%m/%Y') as meeting_date FROM meetings ORDER BY meeting_date DESC, id DESC";
        $result = $mysqli->query($sql);
        $meetings = [];
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                // handle both column names: audio_path or audio_file_path
                if (empty($row['audio_path']) && !empty($row['audio_file_path'])) {
                    $row['audio_path'] = $row['audio_file_path'];
                }
                // decode photos / related_photos JSON
                $photosRaw = $row['related_photos'] ?? $row['photos'] ?? '[]';
                $row['photos'] = is_string($photosRaw) ? (json_decode($photosRaw, true) ?: []) : ($photosRaw ?: []);
                $meetings[] = $row;
            }
        }
        apiResponse(['success' => true, 'status' => 'success', 'meetings' => $meetings, 'data' => $meetings]);
        break;

    case 'summarize_meeting':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $mid = (int)($_POST['meeting_id'] ?? 0);
        if (!$mid) apiResponse(['success' => false, 'message' => 'Missing meeting ID']);
        $forceRegenerate = !empty($_POST['force']) && $_POST['force'] !== '0';

        $res = $mysqli->query("SELECT * FROM meetings WHERE id = $mid LIMIT 1");
        $meeting = $res ? $res->fetch_assoc() : null;
        if (!$meeting) apiResponse(['success' => false, 'message' => 'Meeting not found']);

        $existingSummary = trim((string)($meeting['summary'] ?? ''));
        $existingTranscript = trim((string)($meeting['transcript_text'] ?? ''));

        if (!$forceRegenerate && $existingSummary !== '' && $existingTranscript !== '') {
            $analysisExisting = [];
            $summaryJsonRaw = $meeting['summary_json'] ?? '';
            if (is_string($summaryJsonRaw) && trim($summaryJsonRaw) !== '') {
                $decoded = json_decode($summaryJsonRaw, true);
                if (is_array($decoded)) {
                    $analysisExisting = $decoded;
                }
            }

            apiResponse([
                'success' => true,
                'summary' => $existingSummary,
                'transcript' => $existingTranscript,
                'analysis' => $analysisExisting,
                'transcript_provider' => $meeting['transcript_provider'] ?? null,
                'transcript_model' => $meeting['transcript_model'] ?? null,
                'summary_provider' => $meeting['summary_provider'] ?? null,
                'summary_model' => $meeting['summary_model'] ?? null,
                'generated_at' => $meeting['summary_generated_at'] ?? null,
                'cached' => true,
            ]);
        }

        $localOnly = meeting_ai_local_only_enabled();
        $workerConfig = meeting_ai_get_worker_config();
        $summaryJobId = trim((string)($meeting['summary_job_id'] ?? ''));
        $summaryJobStatus = strtolower(trim((string)($meeting['summary_job_status'] ?? '')));
        $summaryJobMessage = trim((string)($meeting['summary_job_message'] ?? ''));

        if ($localOnly) {
            if (empty($workerConfig['enabled'])) {
                apiResponse([
                    'success' => false,
                    'message' => 'Local AI mode is enabled, but MEETING_AI_WORKER_URL is not configured yet.',
                ]);
            }

            if ($forceRegenerate) {
                meeting_ai_reset_meeting_summary_state($mysqli, $mid);
                $meeting['summary'] = '';
                $meeting['summary_json'] = null;
                $meeting['transcript_text'] = '';
                $existingTranscript = '';
                $summaryJobId = '';
                $summaryJobStatus = '';
                $summaryJobMessage = '';
            }

            if ($summaryJobId !== '' && in_array($summaryJobStatus, ['queued', 'running'], true)) {
                apiResponse([
                    'success' => true,
                    'processing' => true,
                    'job_id' => $summaryJobId,
                    'job_status' => $summaryJobStatus,
                    'message' => $summaryJobMessage !== '' ? $summaryJobMessage : 'Local AI worker is still processing this meeting.',
                ]);
            }

            $jobStart = meeting_ai_start_worker_summary_job($meeting, $existingTranscript);
            if (!$jobStart['attempted'] || !$jobStart['success']) {
                apiResponse([
                    'success' => false,
                    'message' => $jobStart['message'] ?? 'Unable to start local AI worker job.',
                    'local_only' => true,
                ]);
            }

            meeting_ai_update_meeting_job_state(
                $mysqli,
                $mid,
                (string)$jobStart['job_id'],
                (string)($jobStart['job_status'] ?? 'queued'),
                (string)($jobStart['message'] ?? '')
            );

            apiResponse([
                'success' => true,
                'processing' => true,
                'job_id' => $jobStart['job_id'],
                'job_status' => $jobStart['job_status'] ?? 'queued',
                'message' => $jobStart['message'] ?? 'Meeting summary job started.',
                'local_only' => true,
            ]);
        }

        $audioPath = trim((string)($meeting['audio_path'] ?? $meeting['audio_file_path'] ?? ''));
        $transcriptText = $existingTranscript;
        $transcriptProvider = trim((string)($meeting['transcript_provider'] ?? ''));
        $transcriptModel = trim((string)($meeting['transcript_model'] ?? ''));
        $summaryText = '';
        $analysis = [];
        $summaryProvider = '';
        $summaryModel = '';
        $workerError = '';

        $workerSummary = meeting_ai_request_worker_summary($meeting, $existingTranscript);
        if (!empty($workerSummary['attempted'])) {
            if (!empty($workerSummary['success'])) {
                $transcriptText = trim((string)($workerSummary['transcript'] ?? $transcriptText));
                $transcriptProvider = trim((string)($workerSummary['transcript_provider'] ?? 'local-worker'));
                $transcriptModel = trim((string)($workerSummary['transcript_model'] ?? 'faster-whisper'));
                $summaryText = trim((string)($workerSummary['summary'] ?? ''));
                $analysis = is_array($workerSummary['analysis'] ?? null) ? $workerSummary['analysis'] : [];
                $summaryProvider = trim((string)($workerSummary['summary_provider'] ?? 'local-worker'));
                $summaryModel = trim((string)($workerSummary['summary_model'] ?? 'ollama'));
            } else {
                $workerError = trim((string)($workerSummary['message'] ?? ''));
            }
        }

        if ($localOnly && $summaryText === '') {
            $message = 'Local AI worker could not summarize this meeting.';
            if ($workerError !== '') {
                $message = 'Local AI worker failed: ' . $workerError;
            } elseif ($audioPath === '' && $existingTranscript === '' && trim((string)($meeting['description'] ?? '')) === '') {
                $message = 'Local AI worker could not summarize this meeting because no audio, transcript, or description was available.';
            }
            apiResponse([
                'success' => false,
                'message' => $message,
                'local_only' => true,
            ]);
        }

        if ($summaryText === '') {
            if ($forceRegenerate || $transcriptText === '') {
                if ($audioPath !== '') {
                    $resolvedAudio = meeting_ai_resolve_audio_path($audioPath);
                    if (!$resolvedAudio['ok']) {
                        apiResponse([
                            'success' => false,
                            'message' => $resolvedAudio['message'] ?? 'Unable to locate meeting audio.',
                        ]);
                    }

                    $transcription = meeting_ai_transcribe_audio_file($resolvedAudio['path'], $meeting);
                    if (!empty($resolvedAudio['cleanup']) && !empty($resolvedAudio['path']) && is_file($resolvedAudio['path'])) {
                        @unlink($resolvedAudio['path']);
                    }

                    if (!$transcription['success']) {
                        $message = $transcription['message'] ?? 'Transcription failed.';
                        if ($workerError !== '') {
                            $message = 'AI Worker failed: ' . $workerError . ' Fallback provider failed: ' . $message;
                        }
                        apiResponse([
                            'success' => false,
                            'message' => $message,
                        ]);
                    }

                    $transcriptText = trim((string)($transcription['text'] ?? ''));
                    $transcriptProvider = trim((string)($transcription['provider'] ?? ''));
                    $transcriptModel = trim((string)($transcription['model'] ?? ''));
                } else {
                    $transcriptText = trim((string)($meeting['description'] ?? ''));
                    $transcriptProvider = 'local';
                    $transcriptModel = 'description-fallback';
                }
            }

            if ($transcriptText === '') {
                $message = 'No transcript text could be created from this meeting.';
                if ($workerError !== '') {
                    $message = 'AI Worker failed: ' . $workerError . ' Fallback provider failed: ' . $message;
                }
                apiResponse([
                    'success' => false,
                    'message' => $message,
                ]);
            }

            $summaryPayload = meeting_ai_generate_summary_payload($meeting, $transcriptText);
            if (!$summaryPayload['success']) {
                $message = $summaryPayload['message'] ?? 'Summary generation failed.';
                if ($workerError !== '') {
                    $message = 'AI Worker failed: ' . $workerError . ' Fallback provider failed: ' . $message;
                }
                apiResponse([
                    'success' => false,
                    'message' => $message,
                ]);
            }

            $summaryText = trim((string)($summaryPayload['summary'] ?? ''));
            $analysis = is_array($summaryPayload['analysis'] ?? null) ? $summaryPayload['analysis'] : [];
            $summaryProvider = trim((string)($summaryPayload['provider'] ?? ''));
            $summaryModel = trim((string)($summaryPayload['model'] ?? ''));
        }

        $summaryJson = json_encode($analysis, JSON_UNESCAPED_UNICODE);

        $stmt = $mysqli->prepare("UPDATE meetings
            SET transcript_text = ?,
                transcript_provider = ?,
                transcript_model = ?,
                summary = ?,
                summary_json = ?,
                summary_generated_at = NOW(),
                summary_provider = ?,
                summary_model = ?
            WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param(
                "sssssssi",
                $transcriptText,
                $transcriptProvider,
                $transcriptModel,
                $summaryText,
                $summaryJson,
                $summaryProvider,
                $summaryModel,
                $mid
            );
            $stmt->execute();
            $stmt->close();
        }

        apiResponse([
            'success' => true,
            'summary' => $summaryText,
            'transcript' => $transcriptText,
            'analysis' => $analysis,
            'transcript_provider' => $transcriptProvider,
            'transcript_model' => $transcriptModel,
            'summary_provider' => $summaryProvider,
            'summary_model' => $summaryModel,
            'generated_at' => date('Y-m-d H:i:s'),
            'cached' => false,
        ]);
        break;

    case 'get_meeting_summary_status':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $mid = (int)($_POST['meeting_id'] ?? 0);
        if (!$mid) apiResponse(['success' => false, 'message' => 'Missing meeting ID']);

        $res = $mysqli->query("SELECT * FROM meetings WHERE id = $mid LIMIT 1");
        $meeting = $res ? $res->fetch_assoc() : null;
        if (!$meeting) apiResponse(['success' => false, 'message' => 'Meeting not found']);

        $existingSummary = trim((string)($meeting['summary'] ?? ''));
        $existingTranscript = trim((string)($meeting['transcript_text'] ?? ''));
        $summaryJobId = trim((string)($meeting['summary_job_id'] ?? ''));
        $summaryJobStatus = strtolower(trim((string)($meeting['summary_job_status'] ?? '')));
        $summaryJobMessage = trim((string)($meeting['summary_job_message'] ?? ''));

        if ($existingSummary !== '' && $existingTranscript !== '' && !in_array($summaryJobStatus, ['queued', 'running'], true)) {
            $analysisExisting = [];
            $summaryJsonRaw = $meeting['summary_json'] ?? '';
            if (is_string($summaryJsonRaw) && trim($summaryJsonRaw) !== '') {
                $decoded = json_decode($summaryJsonRaw, true);
                if (is_array($decoded)) {
                    $analysisExisting = $decoded;
                }
            }

            apiResponse([
                'success' => true,
                'processing' => false,
                'summary' => $existingSummary,
                'transcript' => $existingTranscript,
                'analysis' => $analysisExisting,
                'transcript_provider' => $meeting['transcript_provider'] ?? null,
                'transcript_model' => $meeting['transcript_model'] ?? null,
                'summary_provider' => $meeting['summary_provider'] ?? null,
                'summary_model' => $meeting['summary_model'] ?? null,
                'generated_at' => $meeting['summary_generated_at'] ?? null,
                'cached' => true,
            ]);
        }

        if (!meeting_ai_local_only_enabled()) {
            apiResponse([
                'success' => false,
                'message' => 'Meeting summary polling is only used for local AI mode.',
            ]);
        }

        if ($summaryJobId === '') {
            apiResponse([
                'success' => false,
                'message' => 'No active local AI worker job was found for this meeting.',
            ]);
        }

        $jobStatusResponse = meeting_ai_get_worker_job_status($summaryJobId);
        if (!$jobStatusResponse['attempted']) {
            apiResponse([
                'success' => false,
                'message' => $jobStatusResponse['message'] ?? 'Unable to check local AI worker status.',
            ]);
        }

        if (!empty($jobStatusResponse['processing'])) {
            meeting_ai_update_meeting_job_state(
                $mysqli,
                $mid,
                $summaryJobId,
                (string)($jobStatusResponse['job_status'] ?? 'running'),
                (string)($jobStatusResponse['message'] ?? $summaryJobMessage)
            );

            apiResponse([
                'success' => true,
                'processing' => true,
                'job_id' => $summaryJobId,
                'job_status' => $jobStatusResponse['job_status'] ?? 'running',
                'message' => $jobStatusResponse['message'] ?? 'Local AI worker is still processing this meeting.',
                'local_only' => true,
            ]);
        }

        if (!$jobStatusResponse['success']) {
            meeting_ai_update_meeting_job_state(
                $mysqli,
                $mid,
                $summaryJobId,
                (string)($jobStatusResponse['job_status'] ?? 'failed'),
                (string)($jobStatusResponse['message'] ?? 'Local AI worker job failed.')
            );

            apiResponse([
                'success' => false,
                'message' => $jobStatusResponse['message'] ?? 'Local AI worker job failed.',
                'local_only' => true,
            ]);
        }

        $stored = meeting_ai_store_completed_summary($mysqli, $mid, $jobStatusResponse);

        apiResponse([
            'success' => true,
            'processing' => false,
            'summary' => $stored['summary'],
            'transcript' => $stored['transcript'],
            'analysis' => $stored['analysis'],
            'transcript_provider' => $stored['transcript_provider'],
            'transcript_model' => $stored['transcript_model'],
            'summary_provider' => $stored['summary_provider'],
            'summary_model' => $stored['summary_model'],
            'generated_at' => date('Y-m-d H:i:s'),
            'cached' => false,
            'local_only' => true,
        ]);
        break;

    case 'summarize_meeting_legacy':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $mid = (int)($_POST['meeting_id'] ?? 0);
        if (!$mid) apiResponse(['success' => false, 'message' => 'Missing meeting ID']);

        $res = $mysqli->query("SELECT * FROM meetings WHERE id = $mid LIMIT 1");
        $meeting = $res ? $res->fetch_assoc() : null;
        if (!$meeting) apiResponse(['success' => false, 'message' => 'Meeting not found']);

        // --- GROQ API INTEGRATION (Whisper for Transcription + Llama for Summary) ---
        $groqApiKey = "gsk_7Mtp" . "fnHCuOnZNT2nSCs7WGdyb3FYZ8xMO8RzEq0QhdyI220d9gaB";
        $desc = $meeting['description'] ?? '';
        $topic = $meeting['topic'] ?? '';
        $audioPath = $meeting['audio_path'] ?? $meeting['audio_file_path'] ?? '';

        $tempUsed = false;
        $fullPath = '';

        // AUTO-CONVERT to Full URL (ensure it matches what the app plays)
        $actualAudioUrl = $audioPath;
        if (!empty($audioPath) && strpos($audioPath, 'http') !== 0) {
            $actualAudioUrl = "https://app.vvc.asia/flutter/" . ltrim($audioPath, '/\\');
        }

        // Fetch from URL
        if (!empty($actualAudioUrl) && strpos($actualAudioUrl, 'http') === 0) {
            $audioContent = @file_get_contents($actualAudioUrl);
            if ($audioContent) {
                $tempPath = tempnam(sys_get_temp_dir(), 'agroq_');
                file_put_contents($tempPath, $audioContent);
                $fullPath = $tempPath;
                $tempUsed = true;
            }
        } else {
            // Local fallback
            $cleanPath = ltrim($audioPath, '/\\');
            $fullPath = __DIR__ . DIRECTORY_SEPARATOR . str_replace(['/', '\\'], DIRECTORY_SEPARATOR, $cleanPath);
        }

        $transcribedText = $desc;

        // STEP 1: Transcribe via Groq Whisper
        if (file_exists($fullPath) && is_file($fullPath)) {
            $ch = curl_init("https://api.groq.com/openai/v1/audio/transcriptions");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $groqApiKey"]);
            curl_setopt($ch, CURLOPT_POSTFIELDS, [
                'file' => new CURLFile($fullPath),
                'model' => 'whisper-large-v3',
                'language' => 'km',
                'response_format' => 'json'
            ]);
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $jsonExec = curl_exec($ch);
            $result = json_decode($jsonExec, true);
            curl_close($ch);

            if (isset($result['text'])) {
                $transcribedText = $result['text'];
                if (strlen($desc) > 10) $transcribedText .= "\n\n(Context: $desc)";
            } else {
                // EXPOSE ERROR: Tell why transcription failed
                $transcribedText = "!!! TRANSCRIPTION_FAILED: " . (isset($result['error']['message']) ? $result['error']['message'] : json_encode($result));
            }
            if ($tempUsed && file_exists($fullPath)) { @unlink($fullPath); }
        }

        $fileError = "";
        if (!empty($audioPath) && !$tempUsed && !file_exists($fullPath)) {
            $fileError = " [រកមិនឃើញសំឡេង: $actualAudioUrl]";
        }

        if (empty($transcribedText) || strlen($transcribedText) < 10) {
            $summary = "ព័ត៌មានមិនគ្រប់គ្រាន់ដើម្បីសង្ខេប (Insufficient info) " . $fileError . " (Desc: " . strlen($desc) . ")";
        } else {
            $prompt = "អ្នកគឺជាជំនួយការសង្ខេបកិច្ចប្រជុំដ៏ឆ្លាតវៃ។ សូមជួយសង្ខេបកិច្ចប្រជុំដែលមានប្រធានបទ '$topic' និងខ្លឹមសារខាងក្រោមជាភាសាខ្មែរ បែងចែកជា ៣ ផ្នែក (គោលបំណង, ចំណុចសំខាន់ៗ, សកម្មភាពបន្ត)៖\n\n$transcribedText";
            $ch = curl_init("https://api.groq.com/openai/v1/chat/completions");
            curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
            curl_setopt($ch, CURLOPT_POST, true);
            curl_setopt($ch, CURLOPT_HTTPHEADER, ["Authorization: Bearer $groqApiKey", "Content-Type: application/json"]);
            $postData = [
                "model" => "llama-3.3-70b-versatile",
                "messages" => [
                    ["role" => "system", "content" => "You summarize meetings in Khmer."],
                    ["role" => "user", "content" => $prompt]
                ],
                "temperature" => 0.5
            ];
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($postData));
            curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
            $jsonResponse = curl_exec($ch);
            $err = curl_error($ch);
            $res = json_decode($jsonResponse, true);
            curl_close($ch);

            if ($err) {
                $summary = "កំហុសបច្ចេកទេសក្នុង Groq: " . $err;
            } else {
                $summary = $res['choices'][0]['message']['content'] ?? ("Groq Summary Error: " . (isset($res['error']['message']) ? $res['error']['message'] : json_encode($res)));
            }
        }

        // Save summary to database
        $stmt = $mysqli->prepare("UPDATE meetings SET summary = ? WHERE id = ?");
        $stmt->bind_param("si", $summary, $mid);
        $stmt->execute();

        apiResponse(['success' => true, 'summary' => $summary]);
        break;

    case 'get_my_mission_letters':
    case 'get_mission_letters':
        if (!$user) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Unauthorized']);
        $eid = $user['employee_id'];
        $sql = "SELECT *,
                       DATE_FORMAT(start_date, '%d/%m/%Y') as start_date_fmt,
                       DATE_FORMAT(end_date, '%d/%m/%Y') as end_date_fmt,
                       DATE_FORMAT(created_at, '%d/%m/%Y %h:%i %p') as created_at_fmt
                FROM mission_letters
                WHERE employee_id = ?
                ORDER BY id DESC LIMIT 50";
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) apiResponse(['success' => false, 'status' => 'error', 'message' => $mysqli->error]);
        $stmt->bind_param("s", $eid);
        $stmt->execute();
        $res = $stmt->get_result();
        $data = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) { $data[] = $row; }
        } else {
            $stmt->store_result();
            $meta = $stmt->result_metadata();
            $row = [];
            $params = [];
            while ($meta && $field = $meta->fetch_field()) { $params[] = &$row[$field->name]; }
            if (!empty($params)) {
                call_user_func_array([$stmt, 'bind_result'], $params);
                while ($stmt->fetch()) {
                    $tmp = [];
                    foreach ($row as $key => $val) { $tmp[$key] = $val; }
                    $data[] = $tmp;
                }
            }
        }
        apiResponse(['success' => true, 'status' => 'success', 'data' => $data]);
        break;

    case 'api_login':
        // Scan-based login
        $eid = trim($_POST['employee_id'] ?? '');
        $req_password = trim($_POST['password'] ?? '');
        if (empty($eid)) apiResponse(['success' => false, 'message' => 'Employee ID required']);

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
        $base = null;
        if ($stmt) {
            $stmt->bind_param("s", $eid);
            $stmt->execute();
            $result = $stmt->get_result();
            if ($result) {
                $base = $result->fetch_assoc();
            } else {
                $stmt->store_result();
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result($b_eid, $b_name, $b_role, $b_avatar, $b_sys_role, $b_sys_label, $b_dept, $b_pos, $b_phone, $b_email, $b_pass, $b_creator, $b_max, $b_verified);
                    $stmt->fetch();
                    $base = ['employee_id' => $b_eid, 'name' => $b_name, 'user_role' => $b_role, 'avatar' => $b_avatar,
                             'system_role' => $b_sys_role, 'system_role_label' => $b_sys_label, 'department' => $b_dept, 'position' => $b_pos,
                             'phone' => $b_phone, 'email' => $b_email, 'password' => $b_pass,
                             'created_by_admin_id' => $b_creator, 'global_max_tokens' => $b_max, 'is_verified' => $b_verified];
                }
            }
            $stmt->close();
        }

        if ($base) {
            // Password check: if password is set, verify it. If blank, allow any.
            if (!empty($base['password']) && !empty($req_password)) {
                if (!password_verify($req_password, $base['password'])) {
                    apiResponse(['success' => false, 'message' => 'លេខសម្ងាត់មិនត្រឹមត្រូវ']);
                }
            }

            // CHECK ACTIVE TOKENS LIMIT
            $admin_id_for_limit = $base['created_by_admin_id'];
            if (empty($admin_id_for_limit) || $base['user_role'] === 'Admin') {
                $admin_id_for_limit = $base['employee_id'];
            }

            $max_tokens = 1;
            $res_limit = $mysqli->query("SELECT global_max_tokens FROM users WHERE employee_id = '$admin_id_for_limit' LIMIT 1");
            if ($res_limit && $row_limit = $res_limit->fetch_assoc()) {
                $max_tokens = (int)($row_limit['global_max_tokens'] ?? 1);
            }

            $res_count = $mysqli->query("SELECT COUNT(*) as active_count FROM active_tokens WHERE employee_id = '{$base['employee_id']}'");
            $active_count = 0;
            if ($res_count && $row_count = $res_count->fetch_assoc()) {
                $active_count = (int)$row_count['active_count'];
            }

            if ($active_count >= $max_tokens) {
                apiResponse(['success' => false, 'message' => "គណនីនេះច្បងបាន Login លើសចំនួនឧបករណ៍ ($active_count/$max_tokens)។ សូម Logout ពីឧបករណ៍ចាស់សិន។"]);
            }

            $newToken = bin2hex(random_bytes(32));
            $mysqli->query("INSERT INTO active_tokens (employee_id, auth_token) VALUES ('{$base['employee_id']}', '{$newToken}')");
            $systemRole = $base['system_role'] ?? 'Employee';
            if (($systemRole === '' || strcasecmp($systemRole, 'Employee') === 0)
                && strcasecmp((string)($base['user_role'] ?? ''), 'Worker') === 0) {
                $systemRole = 'Worker';
            } elseif (($systemRole === '' || strcasecmp($systemRole, 'Employee') === 0)
                && strcasecmp((string)($base['user_role'] ?? ''), 'Admin') === 0) {
                $systemRole = 'Admin';
            }
            $systemRoleLabel = $base['system_role_label'] ?? '';
            $displayRole = !empty($systemRoleLabel) ? $systemRoleLabel : (function_exists('app_system_role_label') ? app_system_role_label($systemRole) : $systemRole);
            $loginEmail = !empty($base['email']) ? $base['email'] : ($base['employee_id'] . '@vvc.com');
            $streak = getAttendanceStreak($mysqli, $base['employee_id']);
            $faceScanEnabled = get_scan_setting('face_scan_enabled', '1', $mysqli);
            apiResponse([
                'success' => true,
                'token' => $newToken,
                'user' => [
                    'id' => $base['employee_id'],
                    'name' => $base['name'],
                    'avatar' => $base['avatar'],
                    'department' => $base['department'] ?? '',
                    'position' => $base['position'] ?? '',
                    'phone' => $base['phone'] ?? '',
                    'email' => $loginEmail,
                    'role' => $base['user_role'],
                    'system_role' => $systemRole,
                    'system_role_label' => $displayRole,
                    'is_verified' => (int)($base['is_verified'] ?? 0),
                    'attendance_streak' => $streak,
                    'face_scan_enabled' => (($faceScanEnabled === '1' || $faceScanEnabled === 1) ? 1 : 0),
                    'face_registered' => (int)($base['face_registered'] ?? 0),
                ]
            ]);
        } else {
            apiResponse(['success' => false, 'message' => 'User not found']);
        }
        break;

    case 'reverse_geocode':
        $lat = floatval($_POST['latitude'] ?? 0);
        $lon = floatval($_POST['longitude'] ?? 0);
        if (!$lat || !$lon) {
            apiResponse(['success' => false, 'message' => 'Missing coordinates']);
        }
        $address = get_address_from_gps($lat, $lon);
        apiResponse(['success' => true, 'address' => $address]);
        break;

    case 'get_profile':
        if (!$user) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }

        $eid = $_POST['employee_id'] ?? $user['employee_id'] ?? '';
        if ($eid === '') {
            apiResponse(['success' => false, 'message' => 'Missing employee id']);
        }

        $sql = "SELECT employee_id, name, avatar, department, position, user_role,
                       COALESCE(system_role, 'Employee') AS system_role,
                       COALESCE(system_role_label, '') AS system_role_label,
                       branch, workplace, phone, COALESCE(email, '') AS email, base_salary,
                       COALESCE(is_verified, 0) AS is_verified,
                       COALESCE(face_registered, 0) AS face_registered
                FROM users
                WHERE employee_id = ?
                LIMIT 1";
        $stmt = $mysqli->prepare($sql);
        $profile = null;
        if ($stmt) {
            $stmt->bind_param("s", $eid);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res) {
                $profile = $res->fetch_assoc();
            } else {
                $stmt->store_result();
                if ($stmt->num_rows > 0) {
                    $stmt->bind_result(
                        $p_emp,
                        $p_name,
                        $p_avatar,
                        $p_dept,
                        $p_pos,
                        $p_role,
                        $p_sys_role,
                        $p_sys_label,
                        $p_branch,
                        $p_workplace,
                        $p_phone,
                        $p_email,
                        $p_salary,
                        $p_verified,
                        $p_face_registered
                    );
                    $stmt->fetch();
                    $profile = [
                        'employee_id' => $p_emp,
                        'name' => $p_name,
                        'avatar' => $p_avatar,
                        'department' => $p_dept,
                        'position' => $p_pos,
                        'user_role' => $p_role,
                        'system_role' => $p_sys_role,
                        'system_role_label' => $p_sys_label,
                        'branch' => $p_branch,
                        'workplace' => $p_workplace,
                        'phone' => $p_phone,
                        'email' => $p_email,
                        'base_salary' => $p_salary,
                        'is_verified' => $p_verified,
                        'face_registered' => $p_face_registered,
                    ];
                }
            }
            $stmt->close();
        }

        if (!$profile) {
            apiResponse(['success' => false, 'message' => 'User not found']);
        }

        $streak = getAttendanceStreak($mysqli, $eid);
        $profileEmail = !empty($profile['email']) ? $profile['email'] : ($profile['employee_id'] . '@vvc.com');

        $profileSystemRole = $profile['system_role'] ?? 'Employee';
        if (($profileSystemRole === '' || strcasecmp($profileSystemRole, 'Employee') === 0)
            && strcasecmp((string)($profile['user_role'] ?? ''), 'Worker') === 0) {
            $profileSystemRole = 'Worker';
        } elseif (($profileSystemRole === '' || strcasecmp($profileSystemRole, 'Employee') === 0)
            && strcasecmp((string)($profile['user_role'] ?? ''), 'Admin') === 0) {
            $profileSystemRole = 'Admin';
        }
        $profileSystemRoleLabel = trim((string) ($profile['system_role_label'] ?? ''));
        if ($profileSystemRoleLabel === '') {
            $profileSystemRoleLabel = function_exists('app_system_role_label') ? app_system_role_label($profileSystemRole) : $profileSystemRole;
        }
        $faceScanEnabled = get_scan_setting('face_scan_enabled', '1', $mysqli, $eid);

        apiResponse([
            'success' => true,
            'user' => [
                'id' => $profile['employee_id'],
                'name' => $profile['name'],
                'avatar' => $profile['avatar'],
                'department' => $profile['department'],
                'position' => $profile['position'],
                'branch' => $profile['branch'] ?? '',
                'workplace' => $profile['workplace'] ?? '',
                'phone' => $profile['phone'] ?? '',
                'email' => $profileEmail,
                'base_salary' => $profile['base_salary'] ?? 0,
                'role' => $profile['user_role'],
                'system_role' => $profileSystemRole,
                'system_role_label' => $profileSystemRoleLabel,
                'is_verified' => (int)($profile['is_verified'] ?? 0),
                'attendance_streak' => $streak,
                'face_scan_enabled' => (($faceScanEnabled === '1' || $faceScanEnabled === 1) ? 1 : 0),
                'face_registered' => (int)($profile['face_registered'] ?? 0),
            ],
        ]);
        break;

    case 'get_dashboard_stats':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $eid         = $user['employee_id'];
        $uid         = (int)$user['id'];
        $uname_fetch = $user['name'] ?? '';

        // 1. Today's Work (Check-ins)
        $todayWork = 0;
        // Use range scan so MySQL can use index on (employee_id, log_datetime)
        $qWork = $mysqli->prepare(
            "SELECT COUNT(*)
             FROM checkin_logs
             WHERE employee_id = ?
               AND log_datetime >= CURDATE()
               AND log_datetime < DATE_ADD(CURDATE(), INTERVAL 1 DAY)"
        );
        if ($qWork) {
            $qWork->bind_param("s", $eid);
            $qWork->execute();
            $res = $qWork->get_result();
            if ($res) {
                $row = $res->fetch_row();
                $todayWork = $row[0] ?? 0;
            }
            $qWork->close();
        }

        // 2. Pending Requests
        $requestsCount = 0;
        $sysRole = $user['system_role'] ?? 'Employee';

        if ($sysRole === 'Admin' || $sysRole === 'HRM') {
            // Admins/HRM see total pending in system
            $qReq = $mysqli->query("SELECT COUNT(*) FROM requests WHERE status = 'pending'");
            if ($qReq) {
                $row = $qReq->fetch_row();
                $requestsCount = $row[0] ?? 0;
            }
        } else {
            // Normal users see only their pending
            $qReq = $mysqli->prepare("SELECT COUNT(*) FROM requests WHERE user_id = ? AND status = 'pending'");
            if ($qReq) {
                $qReq->bind_param("i", $uid);
                $qReq->execute();
                $res = $qReq->get_result();
                if ($res) {
                    $row = $res->fetch_row();
                    $requestsCount = $row[0] ?? 0;
                }
                $qReq->close();
            }
            // fallback: match by requester_name if user_id match failed
            if ($requestsCount == 0) {
                $qReq2 = $mysqli->prepare("SELECT COUNT(*) FROM requests WHERE requester_name = ? AND status = 'pending'");
                if ($qReq2) {
                    $qReq2->bind_param("s", $uname_fetch);
                    $qReq2->execute();
                    $res2 = $qReq2->get_result();
                    if ($res2) {
                        $row2 = $res2->fetch_row();
                        $requestsCount = $row2[0] ?? 0;
                    }
                    $qReq2->close();
                }
            }
        }

        // 3. Announcements
        $announcementsCount = 0;
        $qAnn = $mysqli->query("SELECT COUNT(*) FROM announcements");
        if ($qAnn) {
            $row = $qAnn->fetch_row();
            if ($row) $announcementsCount = $row[0];
        }

        // 4. Annual Leave Remaining (Real balance)
        $leaveRemaining = 0;
        $qBal = $mysqli->prepare("SELECT annual_leave_balance FROM users WHERE employee_id = ? LIMIT 1");
        if ($qBal) {
            $qBal->bind_param("s", $eid);
            $qBal->execute();
            $res = $qBal->get_result();
            if ($res) {
                $resBal = $res->fetch_assoc();
                if ($resBal) {
                    $leaveRemaining = $resBal['annual_leave_balance'] ?? 0;
                }
            }
            $qBal->close();
        }

        // 5. Recent Requests - match by user_id, requester_name, or employee_id join
        $recentRequests = [];
        // Avoid OR (forces scan). Use UNION so indexes can be used.
        $qRecent = $mysqli->prepare(
            "SELECT request_type, status,
                    DATE_FORMAT(created_at, '%d/%m/%Y %h:%i %p') as request_date,
                    id AS created_at_raw
             FROM requests
             WHERE user_id = ?
             UNION ALL
             SELECT request_type, status,
                    DATE_FORMAT(created_at, '%d/%m/%Y %h:%i %p') as request_date,
                    id AS created_at_raw
             FROM requests
             WHERE requester_name = ? AND user_id <> ?
             ORDER BY created_at_raw DESC
             LIMIT 5"
        );
        if ($qRecent) {
            $qRecent->bind_param("isi", $uid, $uname_fetch, $uid);
            $qRecent->execute();
            $res = $qRecent->get_result();
            if ($res) {
                while ($row = $res->fetch_assoc()) {
                    unset($row['created_at_raw']);
                    $recentRequests[] = $row;
                }
            }
            $qRecent->close();
        }
        // fallback recent: join with users table
        if (empty($recentRequests) && $eid !== '') {
            $qRec2 = $mysqli->prepare(
                "SELECT r.request_type, r.status, DATE_FORMAT(r.created_at, '%d/%m/%Y %h:%i %p') as request_date
                 FROM requests r JOIN users u ON r.user_id = u.id
                 WHERE u.employee_id = ?
                 ORDER BY r.id DESC LIMIT 5"
            );
            if ($qRec2) {
                $qRec2->bind_param("s", $eid);
                $qRec2->execute();
                $res2 = $qRec2->get_result();
                if ($res2) while ($row = $res2->fetch_assoc()) $recentRequests[] = $row;
                $qRec2->close();
            }
        }

        // 6. Unread Notifications Count (Unified)
        $unreadNids = 0;
        $qUnread = $mysqli->prepare("SELECT COUNT(*) FROM user_notifications WHERE employee_id = ? AND is_read = 0");
        if ($qUnread) {
            $qUnread->bind_param("s", $eid);
            $qUnread->execute();
            $res = $qUnread->get_result();
            if ($res) {
                $row = $res->fetch_row();
                $unreadNids = (int)($row[0] ?? 0);
            }
            $qUnread->close();
        }

        // For Admins/HRM, we no longer add pending requests to the unread badge.
        // The badge will exclusively track truly unread notifications (is_read=0)
        // so that it clears immediately when the user views the notifications tab.

        apiResponse([
            'success' => true,
            'stats' => [
                'today_work' => (int)$todayWork,
                'requests_count' => (int)$requestsCount,
                'announcements_count' => (int)$announcementsCount,
                'unread_notifications' => $unreadNids,
                'annual_leave_remaining' => floatval($leaveRemaining)
            ],
            'recent_requests' => $recentRequests
        ]);
        break;

    case 'send_app_notification':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $title = trim($_POST['notification_title'] ?? '');
        $message = trim($_POST['notification_message'] ?? '');
        $target_type = $_POST['recipient_type'] ?? 'all';
        $target_roles = isset($_POST['target_roles']) ? (is_array($_POST['target_roles']) ? $_POST['target_roles'] : explode(',', $_POST['target_roles'])) : [];
        $target_users = isset($_POST['target_users']) ? (is_array($_POST['target_users']) ? $_POST['target_users'] : explode(',', $_POST['target_users'])) : [];
        $expiry_date = $_POST['expiry_date'] ?? null;
        if (!empty($expiry_date)) {
            $expiry_date = substr($expiry_date, 0, 10);
        }
        $current_admin_id = $user['id'];

        if (empty($title) || empty($message)) {
            apiResponse(['success' => false, 'status' => 'error', 'message' => 'សូមបញ្ចូលចំណងជើង និងសារ!']);
        }

        require_once 'notification_functions.php';
        $success_count = 0;

        if ($target_type === 'all') {
            $r = $mysqli->query("SELECT DISTINCT system_role FROM users WHERE system_role IS NOT NULL AND system_role != ''");
            $all_roles = [];
            if ($r) {
                while ($row = $r->fetch_assoc()) $all_roles[] = $row['system_role'];
            }
            if (empty($all_roles)) $all_roles = ['Employee', 'Worker', 'Admin', 'HRM'];

            if (sendAppNotificationToRoles($mysqli, $all_roles, $title, $message, $current_admin_id, $expiry_date)) {
                $success_count = 1;
            }
        } elseif ($target_type === 'role') {
            if (empty($target_roles)) {
                apiResponse(['success' => false, 'status' => 'error', 'message' => 'សូមជ្រើសរើសតួនាទីយ៉ាងហោចណាស់មួយ!']);
            }
            if (sendAppNotificationToRoles($mysqli, $target_roles, $title, $message, $current_admin_id, $expiry_date)) {
                $success_count = count($target_roles);
            }
        } elseif ($target_type === 'user') {
            if (empty($target_users)) {
                apiResponse(['success' => false, 'status' => 'error', 'message' => 'សូមជ្រើសរើសអ្នកប្រើប្រាស់យ៉ាងហោចណាស់ម្នាក់!']);
            }
            foreach ($target_users as $uid) {
                if (sendAppNotificationToUser($mysqli, $uid, $title, $message, $current_admin_id, $expiry_date)) {
                    $success_count++;
                }
            }
        }

        if ($success_count > 0) {
            apiResponse(['success' => true, 'status' => 'success', 'message' => 'សារជូនដំណឹងត្រូវបានផ្ញើដោយជោគជ័យ!']);
        } else {
            apiResponse(['success' => false, 'status' => 'error', 'message' => 'មានបញ្ហាក្នុងការផ្ញើសារជូនដំណឹង។']);
        }
        break;

    case 'fetch_last_action':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $eid = $user['employee_id'];
        $today_start = date('Y-m-d 00:00:00');
        $stmt = $mysqli->prepare("SELECT action_type FROM checkin_logs WHERE employee_id = ? AND log_datetime >= ? ORDER BY log_datetime DESC LIMIT 1");
        $last_action = 'Check-Out'; // Default suggestion for start of day
        if ($stmt) {
            $stmt->bind_param("ss", $eid, $today_start);
            $stmt->execute();
            $res_obj = $stmt->get_result();
            if ($res_obj) {
                $res = $res_obj->fetch_assoc();
                if ($res) $last_action = $res['action_type'];
            }
            $stmt->close();
        }
        apiResponse(['success' => true, 'last_action' => $last_action]);
        break;

    case 'fetch_requests':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $uid      = (int)$user['id'];
        $eid      = $user['employee_id'] ?? '';
        $sysRole  = $user['system_role'] ?? 'Employee';
        $limit    = (int)($_POST['limit'] ?? 100);
        if ($limit <= 0) $limit = 100;
        if ($limit > 200) $limit = 200;
        $data     = [];

        if ($sysRole === 'Admin' || $sysRole === 'HRM') {
            // High-privileged roles see ALL requests
            // IMPORTANT: avoid returning heavy LONGTEXT/base64 signature fields in list responses.
            // FIX: Join on both user_id and requester_name to ensure avatar matches the displayed name.
            // u = user by user_id, u2 = user matched by requester_name (for correct avatar)
            $sql = "SELECT
                        r.id, r.user_id, r.request_type, r.requester_name,
                        r.department, r.position, r.branch,
                        r.request_date, r.return_date,
                        r.time_in, r.time_out,
                        r.number_of_days, r.late_hours,
                        r.forgot_scan_in, r.forgot_scan_out,
                        r.total_hours, r.repay_time_in, r.repay_time_out, r.repay_total_hours,
                        r.reason, r.assigned_to, r.location, r.contact_number,
                        r.department_head_name, r.department_head_signature_date,
                        r.signature_date,
                        r.status, r.created_at,
                        u.name as user_display_name, u.employee_id as user_employee_id,
                        COALESCE(u2.avatar, u.avatar) as user_avatar
                    FROM requests r
                    LEFT JOIN users u ON r.user_id = u.id
                    LEFT JOIN users u2 ON r.requester_name = u2.name AND r.requester_name != ''
                    ORDER BY r.request_date DESC, r.id DESC LIMIT ?";
            $stmtAll = $mysqli->prepare($sql);
            if ($stmtAll) {
                $stmtAll->bind_param("i", $limit);
                $stmtAll->execute();
                $res = $stmtAll->get_result();
                if ($res) while ($row = $res->fetch_assoc()) $data[] = $row;
                $stmtAll->close();
            }
        } else {
            // Normal users see only their own
            // Avoid OR (forces scan). UNION lets MySQL use indexes.
            // FIX: Join on requester_name to get correct avatar matching the displayed name.
            $stmt = $mysqli->prepare(
                "(SELECT
                    r.id, r.user_id, r.request_type, r.requester_name,
                    r.department, r.position, r.branch,
                    r.request_date, r.return_date,
                    r.time_in, r.time_out,
                    r.number_of_days, r.late_hours,
                    r.forgot_scan_in, r.forgot_scan_out,
                    r.total_hours, r.repay_time_in, r.repay_time_out, r.repay_total_hours,
                    r.reason, r.assigned_to, r.location, r.contact_number,
                    r.department_head_name, r.department_head_signature_date,
                    r.signature_date,
                    r.status, r.created_at,
                    COALESCE(u2.avatar, u.avatar) as user_avatar
                  FROM requests r
                  LEFT JOIN users u ON r.user_id = u.id
                  LEFT JOIN users u2 ON r.requester_name = u2.name AND r.requester_name != ''
                  WHERE r.user_id = ?)
                 UNION ALL
                 (SELECT
                    r.id, r.user_id, r.request_type, r.requester_name,
                    r.department, r.position, r.branch,
                    r.request_date, r.return_date,
                    r.time_in, r.time_out,
                    r.number_of_days, r.late_hours,
                    r.forgot_scan_in, r.forgot_scan_out,
                    r.total_hours, r.repay_time_in, r.repay_time_out, r.repay_total_hours,
                    r.reason, r.assigned_to, r.location, r.contact_number,
                    r.department_head_name, r.department_head_signature_date,
                    r.signature_date,
                    r.status, r.created_at,
                    COALESCE(u2.avatar, u.avatar) as user_avatar
                  FROM requests r
                  LEFT JOIN users u ON r.user_id = u.id
                  LEFT JOIN users u2 ON r.requester_name = u2.name AND r.requester_name != ''
                  WHERE r.requester_name = ? AND r.user_id <> ?)
                 ORDER BY id DESC
                 LIMIT ?"
            );
            if ($stmt) {
                $uname = $user['name'] ?? '';
                $stmt->bind_param("isii", $uid, $uname, $uid, $limit);
                $stmt->execute();
                $res = $stmt->get_result();
                if ($res) while ($row = $res->fetch_assoc()) $data[] = $row;
                $stmt->close();
            }

            // Fallback match by employee_id via users JOIN
            if (empty($data) && $eid !== '') {
                $stmtLookup = $mysqli->prepare(
                    "SELECT r.id, r.user_id, r.request_type, r.requester_name,
                            r.department, r.position, r.branch,
                            r.request_date, r.return_date,
                            r.time_in, r.time_out,
                            r.number_of_days, r.late_hours,
                            r.forgot_scan_in, r.forgot_scan_out,
                            r.total_hours, r.repay_time_in, r.repay_time_out, r.repay_total_hours,
                            r.reason, r.assigned_to, r.location, r.contact_number,
                            r.department_head_name, r.department_head_signature_date,
                            r.signature_date,
                            r.status, r.created_at,
                            COALESCE(u2.avatar, u.avatar) as user_avatar
                     FROM requests r
                     JOIN users u ON r.user_id = u.id
                     LEFT JOIN users u2 ON r.requester_name = u2.name AND r.requester_name != ''
                     WHERE u.employee_id = ?
                     ORDER BY r.id DESC LIMIT 100"
                );
                if ($stmtLookup) {
                    $stmtLookup->bind_param("s", $eid);
                    $stmtLookup->execute();
                    $res2 = $stmtLookup->get_result();
                    if ($res2) {
                        while ($row = $res2->fetch_assoc()) {
                            $exists = false;
                            foreach($data as $d) if($d['id'] == $row['id']) { $exists = true; break; }
                            if(!$exists) $data[] = $row;
                        }
                    }
                    $stmtLookup->close();
                }
            }
        }

        apiResponse([
            'success'  => true,
            'requests' => $data,
            'debug' => [
                'role' => $sysRole,
                'count' => count($data),
                'limit' => $limit
            ]
        ]);
        break;

    case 'get_request_signatures':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $rid = (int)($_POST['id'] ?? $_POST['request_id'] ?? 0);
        if ($rid <= 0) apiResponse(['success' => false, 'message' => 'Invalid Request ID']);

        // Only allow owner or Admin/HRM
        $sysRole = $user['system_role'] ?? 'Employee';
        $isPriv = ($sysRole === 'Admin' || $sysRole === 'HRM');

        $check = $mysqli->prepare("SELECT user_id FROM requests WHERE id = ? LIMIT 1");
        if (!$check) apiResponse(['success' => false, 'message' => 'Prepare failed']);
        $check->bind_param("i", $rid);
        $check->execute();
        $row = $check->get_result()->fetch_assoc();
        $check->close();

        if (!$row) apiResponse(['success' => false, 'message' => 'Request not found']);
        if (!$isPriv && (int)$row['user_id'] !== (int)$user['id']) {
            apiResponse(['success' => false, 'message' => 'Permission denied']);
        }

        $stmt = $mysqli->prepare(
            "SELECT
                signature, signature_date,
                department_head_signature, department_head_signature_date
             FROM requests
             WHERE id = ?
             LIMIT 1"
        );
        if (!$stmt) apiResponse(['success' => false, 'message' => 'Prepare failed']);
        $stmt->bind_param("i", $rid);
        $stmt->execute();
        $sigRow = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        apiResponse([
            'success' => true,
            'signatures' => $sigRow ?: []
        ]);
        break;

    case 'submit_request':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $uid = $user['id'];
        $uname = $user['name'] ?? 'Staff';
        $u_eid = $user['employee_id'] ?? '';
        $reqType = $_POST['requestType'] ?? '';
        $formData = json_decode($_POST['formDataJson'] ?? '{}', true);

        // Map fields based on request type and standard HRM schema
        $requestDate = date('Y-m-d');
        $returnDate = $formData['return_date'] ?? null;
        $startTime = $formData['time_in'] ?? null;
        $endTime = $formData['time_out'] ?? null;
        $numDays = isset($formData['number_of_days']) && $formData['number_of_days'] !== '' ? floatval($formData['number_of_days']) : null;
        $remDays = isset($formData['remaining_days']) && $formData['remaining_days'] !== '' ? floatval($formData['remaining_days']) : null;
        $dept = $formData['department'] ?? '';
        $branch = $formData['branch'] ?? '';
        $lateHours = $formData['late_hours'] ?? '';
        $forgotIn = $formData['forgot_scan_in'] ?? '';
        $forgotOut = $formData['forgot_scan_out'] ?? '';
        $totalHours = $formData['total_hours'] ?? '';
        $deptHead = $formData['department_head_name'] ?? '';
        $repayIn = $formData['repay_time_in'] ?? null;
        $repayOut = $formData['repay_time_out'] ?? null;
        $repayTotal = $formData['repay_total_hours'] ?? '';
        $assignedTo = $formData['assigned_to'] ?? '';
        $location = $formData['location'] ?? '';
        $contact = $formData['contact_number'] ?? $formData['leave_contact'] ?? '';
        $position = $formData['position'] ?? '';
        $reason = $formData['reason'] ?? $formData['leave_reason'] ?? $formData['ot_reason'] ?? $formData['late_reason_text'] ?? $formData['late_reason'] ?? $formData['forget_reason'] ?? $formData['change_day_off_reason'] ?? $formData['change_reason'] ?? '';

        // Screen-specific smart mapping
        if ($reqType === 'Leave') {
            $requestDate = $formData['leave_date'] ?? $requestDate;
            if (empty($numDays)) $numDays = isset($formData['leave_total_hours']) ? floatval($formData['leave_total_hours']) : 1.0;
        } elseif ($reqType === 'Overtime' || $reqType === 'OT') {
            $requestDate = $formData['ot_date'] ?? $requestDate;
            if (empty($startTime)) $startTime = $formData['ot_start'] ?? $formData['ot_start_time'] ?? null;
            if (empty($endTime)) $endTime = $formData['ot_end'] ?? $formData['ot_end_time'] ?? null;
        } elseif ($reqType === 'Late') {
            $requestDate = $formData['late_date'] ?? $requestDate;
            if (empty($startTime)) $startTime = $formData['actual_check_in_time'] ?? null;
        } elseif ($reqType === 'Forget-Attendance') {
            $requestDate = $formData['forget_date'] ?? $requestDate;
            if (empty($startTime)) $startTime = $formData['forget_time'] ?? null;
            $fType = $formData['forgetType'] ?? '';
            if (empty($forgotIn)) $forgotIn = ($fType === 'Check-In' || $fType === 'Both') ? 'Yes' : 'No';
            if (empty($forgotOut)) $forgotOut = ($fType === 'Check-Out' || $fType === 'Both') ? 'Yes' : 'No';
        } elseif ($reqType === 'Change-Day-Off') {
            $requestDate = $formData['original_day_off'] ?? $requestDate;
            $returnDate = $formData['new_day_off'] ?? null;
            $location = "New Work Day: " . ($formData['new_work_day'] ?? 'N/A');
        }

        // Auto-pull signature if available (matching submit_request.php logic)
        $sigData = null;
        $sigDate = null;
        $qSig = $mysqli->prepare("SELECT signature, signature_date FROM requests WHERE user_id = ? AND signature IS NOT NULL AND signature != '' ORDER BY id DESC LIMIT 1");
        if ($qSig) {
            $qSig->bind_param("i", $uid);
            $qSig->execute();
            $rSig = $qSig->get_result()->fetch_assoc();
            if ($rSig) {
                $sigData = $rSig['signature'];
                $sigDate = $rSig['signature_date'];
            }
            $qSig->close();
        }

        // Balance Deduction (matching submit_request.php:241)
        if ($reqType === 'Leave' && $numDays > 0) {
           $upBal = $mysqli->prepare("UPDATE users SET annual_leave_balance = annual_leave_balance - ? WHERE id = ?");
           if ($upBal) {
               $upBal->bind_param("di", $numDays, $uid);
               $upBal->execute();
               $upBal->close();
           }
        }

        $deptHeadSig = $formData['department_head_signature'] ?? null;
        $deptHeadSigDate = $deptHeadSig ? date('Y-m-d') : null;

        $sql = "INSERT INTO requests (
            user_id, request_type, requester_name, number_of_days, remaining_days, department, position, branch,
            department_head_name, department_head_signature, department_head_signature_date,
            request_date, return_date, late_hours, forgot_scan_in, forgot_scan_out, time_in, time_out,
            total_hours, repay_time_in, repay_time_out, repay_total_hours, reason, assigned_to, location,
            contact_number, signature, signature_date, status, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())";

        $ins = $mysqli->prepare($sql);
        if ($ins) {
            $status_pending = 'pending';
            $ins->bind_param("issddssssssssssssssssssssssss", $uid, $reqType, $uname, $numDays, $remDays, $dept, $position, $branch, $deptHead, $deptHeadSig, $deptHeadSigDate, $requestDate, $returnDate, $lateHours, $forgotIn, $forgotOut, $startTime, $endTime, $totalHours, $repayIn, $repayOut, $repayTotal, $reason, $assignedTo, $location, $contact, $sigData, $sigDate, $status_pending);
            if ($ins->execute()) {
                $newRequestId = (int) $mysqli->insert_id;
                add_request_workflow_log(
                    $mysqli,
                    $newRequestId,
                    'created',
                    null,
                    'pending',
                    (string) $u_eid,
                    (string) $uname,
                    (string) ($user['system_role'] ?? $user['user_role'] ?? 'Employee'),
                    'Request submitted from API.',
                    [
                        'request_type' => $reqType,
                        'request_date' => $requestDate,
                    ]
                );

                sendRequestTelegram($mysqli, $u_eid, [
                    'name' => $uname,
                    'request_type' => $reqType,
                    'summary' => "Requested $reqType for $requestDate. Reason: $reason"
                ]);

                // App Notification for Admin and HRM
                sendAppNotificationToRoles($mysqli, ['Admin', 'HRM'], "សំណើថ្មី (" . $reqType . ")", "មានសំណើថ្មីពី " . $uname . " (" . $u_eid . ") បានដាក់ជូនហើយ។");

                apiResponse(['success' => true, 'message' => 'សំណើត្រូវបានដាក់ជូនដោយជោគជ័យ']);
            } else {
                apiResponse(['success' => false, 'message' => 'Database error: ' . $mysqli->error]);
            }
            $ins->close();
        } else {
            apiResponse(['success' => false, 'message' => 'Prepare failed: ' . $mysqli->error]);
        }
        break;

    case 'update_request':
        if (!$user) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $rid = (int) ($_POST['id'] ?? 0);
        if ($rid <= 0) {
            apiResponse(['success' => false, 'message' => 'Invalid Request ID']);
        }

        $formData = json_decode($_POST['formDataJson'] ?? '{}', true);
        if (!is_array($formData)) {
            $formData = [];
        }

        $row = null;
        if ($stmt = $mysqli->prepare("SELECT user_id, status FROM requests WHERE id = ? LIMIT 1")) {
            $stmt->bind_param("i", $rid);
            $stmt->execute();
            $res = $stmt->get_result();
            $row = $res ? $res->fetch_assoc() : null;
            $stmt->close();
        }
        if (!$row) {
            apiResponse(['success' => false, 'message' => 'Request not found']);
        }

        $userRole = strtolower((string) ($user['user_role'] ?? ''));
        $systemRole = strtolower((string) ($user['system_role'] ?? ''));
        $isAdmin = in_array($userRole, ['admin', 'hrm'], true) || in_array($systemRole, ['admin', 'hrm'], true);
        if ((int) $row['user_id'] !== (int) ($user['id'] ?? 0) && !$isAdmin) {
            apiResponse(['success' => false, 'message' => 'Permission denied']);
        }

        $fields = [];
        $params = [];
        $types = '';
        $updatedFields = [];
        $allowed = [
            'reason',
            'department_head_name',
            'department_head_signature',
            'number_of_days',
            'request_date',
            'return_date',
            'contact_number',
            'assigned_to',
            'position',
            'department',
            'branch'
        ];

        foreach ($allowed as $key) {
            if (!array_key_exists($key, $formData)) {
                continue;
            }
            $fields[] = "$key = ?";
            $params[] = $formData[$key];
            $types .= 's';
            $updatedFields[] = $key;
        }

        if (empty($fields)) {
            apiResponse(['success' => true, 'message' => 'No changes made']);
        }

        $sql = "UPDATE requests SET " . implode(", ", $fields) . " WHERE id = ?";
        $params[] = $rid;
        $types .= 'i';

        $stmt = $mysqli->prepare($sql);
        $stmt->bind_param($types, ...$params);

        if ($stmt->execute()) {
            add_request_workflow_log(
                $mysqli,
                $rid,
                'updated',
                (string) ($row['status'] ?? ''),
                (string) ($row['status'] ?? ''),
                (string) ($user['employee_id'] ?? ''),
                (string) ($user['name'] ?? ''),
                (string) ($user['system_role'] ?? $user['user_role'] ?? 'Employee'),
                'Request fields updated.',
                ['fields' => $updatedFields]
            );
            apiResponse(['success' => true, 'message' => 'Request updated successfully']);
        } else {
            apiResponse(['success' => false, 'message' => 'Update failed: ' . $mysqli->error]);
        }
        $stmt->close();
        break;

    case 'update_request_legacy':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $rid = (int)($_POST['id'] ?? 0);
        if ($rid <= 0) apiResponse(['success' => false, 'message' => 'Invalid Request ID']);

        $formData = json_decode($_POST['formDataJson'] ?? '{}', true);

        // Only allow update if owner or if admin
        $check = $mysqli->query("SELECT user_id, status FROM requests WHERE id = $rid LIMIT 1");
        $row = $check->fetch_assoc();
        if (!$row) apiResponse(['success' => false, 'message' => 'Request not found']);

        $isAdmin = (isset($user['user_role']) && strtolower($user['user_role']) === 'admin');
        if ($row['user_id'] != $user['id'] && !$isAdmin) {
             apiResponse(['success' => false, 'message' => 'Permission denied']);
        }

        $fields = [];
        $params = [];
        $types = "";

        // List of allowed fields to update
        $allowed = [
            'reason', 'department_head_name', 'department_head_signature',
            'number_of_days', 'request_date', 'return_date', 'contact_number',
            'assigned_to', 'position', 'department', 'branch'
        ];

        foreach ($allowed as $key) {
            if (isset($formData[$key])) {
                $fields[] = "$key = ?";
                $params[] = $formData[$key];
                $types .= "s";
            }
        }

        if (empty($fields)) {
            apiResponse(['success' => true, 'message' => 'No changes made']);
        }

        $sql = "UPDATE requests SET " . implode(", ", $fields) . " WHERE id = ?";
        $params[] = $rid;
        $types .= "i";

        $stmt = $mysqli->prepare($sql);
        $stmt->bind_param($types, ...$params);

        if ($stmt->execute()) {
            apiResponse(['success' => true, 'message' => 'បច្ចុប្បន្នភាពបានជោគជ័យ']);
        } else {
            apiResponse(['success' => false, 'message' => 'Update failed: ' . $mysqli->error]);
        }
        break;

    case 'update_request_status':
        if (!$user || !in_array((string) ($user['system_role'] ?? ''), ['Admin', 'HRM'], true)) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $rid = (int) ($_POST['id'] ?? $_POST['request_id'] ?? 0);
        $newStatus = trim((string) ($_POST['status'] ?? ''));
        if ($rid <= 0 || !in_array($newStatus, ['approved', 'rejected'], true)) {
            apiResponse(['success' => false, 'message' => 'Invalid parameters']);
        }

        $currentStatus = '';
        if ($stmt = $mysqli->prepare("SELECT status FROM requests WHERE id = ? LIMIT 1")) {
            $stmt->bind_param("i", $rid);
            $stmt->execute();
            $res = $stmt->get_result();
            $statusRow = $res ? $res->fetch_assoc() : null;
            $currentStatus = (string) ($statusRow['status'] ?? '');
            $stmt->close();
        }

        $stmt = $mysqli->prepare("UPDATE requests SET status = ?, updated_at = NOW() WHERE id = ?");
        $stmt->bind_param("si", $newStatus, $rid);
        if ($stmt->execute()) {
            add_request_workflow_log(
                $mysqli,
                $rid,
                'status_changed',
                $currentStatus,
                $newStatus,
                (string) ($user['employee_id'] ?? ''),
                (string) ($user['name'] ?? ''),
                (string) ($user['system_role'] ?? 'Admin'),
                'Request status updated from API.',
                []
            );
            apiResponse(['success' => true, 'message' => 'Request status updated']);
        } else {
            apiResponse(['success' => false, 'message' => 'Update failed: ' . $mysqli->error]);
        }
        $stmt->close();
        break;

    case 'update_request_status_legacy':
        if (!$user || !($user['system_role'] === 'Admin' || $user['system_role'] === 'HRM')) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $rid = (int)($_POST['id'] ?? $_POST['request_id'] ?? 0);
        $newStatus = trim($_POST['status'] ?? '');
        if ($rid <= 0 || !in_array($newStatus, ['approved', 'rejected'])) {
            apiResponse(['success' => false, 'message' => 'Invalid parameters']);
        }

        $stmt = $mysqli->prepare("UPDATE requests SET status = ?, updated_at = NOW() WHERE id = ?");
        $stmt->bind_param("si", $newStatus, $rid);
        if ($stmt->execute()) {
            apiResponse(['success' => true, 'message' => ($newStatus === 'approved' ? 'អនុម័តបានជោគជ័យ' : 'បដិសេធបានជោគជ័យ')]);
        } else {
            apiResponse(['success' => false, 'message' => 'Update failed: ' . $mysqli->error]);
        }
        $stmt->close();
        break;

    case 'delete_request':
        if (!$user) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $rid = (int) ($_POST['id'] ?? $_POST['request_id'] ?? 0);
        if ($rid <= 0) {
            apiResponse(['success' => false, 'message' => 'Invalid Request ID']);
        }

        $row = null;
        if ($stmt = $mysqli->prepare("SELECT user_id, status, request_type, number_of_days FROM requests WHERE id = ? LIMIT 1")) {
            $stmt->bind_param("i", $rid);
            $stmt->execute();
            $res = $stmt->get_result();
            $row = $res ? $res->fetch_assoc() : null;
            $stmt->close();
        }
        if (!$row) {
            apiResponse(['success' => false, 'message' => 'Request not found']);
        }

        $isAdmin = in_array((string) ($user['system_role'] ?? ''), ['Admin', 'HRM'], true);
        if ((int) $row['user_id'] !== (int) ($user['id'] ?? 0) && !$isAdmin) {
            apiResponse(['success' => false, 'message' => 'Permission denied']);
        }

        if (($row['status'] ?? '') !== 'pending' && !$isAdmin) {
            apiResponse(['success' => false, 'message' => 'Only pending requests can be deleted']);
        }

        if (($row['request_type'] ?? '') === 'Leave' && ($row['status'] ?? '') === 'pending' && (float) ($row['number_of_days'] ?? 0) > 0) {
            $numDays = (float) $row['number_of_days'];
            $targetUid = (int) $row['user_id'];
            $mysqli->query("UPDATE users SET annual_leave_balance = annual_leave_balance + $numDays WHERE id = $targetUid");
        }

        add_request_workflow_log(
            $mysqli,
            $rid,
            'deleted',
            (string) ($row['status'] ?? ''),
            'deleted',
            (string) ($user['employee_id'] ?? ''),
            (string) ($user['name'] ?? ''),
            (string) ($user['system_role'] ?? $user['user_role'] ?? 'Employee'),
            'Request deleted.',
            ['request_type' => (string) ($row['request_type'] ?? '')]
        );

        if ($mysqli->query("DELETE FROM requests WHERE id = $rid")) {
            apiResponse(['success' => true, 'message' => 'Request deleted successfully']);
        } else {
            apiResponse(['success' => false, 'message' => 'Delete failed: ' . $mysqli->error]);
        }
        break;

    case 'delete_request_legacy':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $rid = (int)($_POST['id'] ?? $_POST['request_id'] ?? 0);
        if ($rid <= 0) apiResponse(['success' => false, 'message' => 'Invalid Request ID']);

        $check = $mysqli->query("SELECT user_id, status, request_type, number_of_days FROM requests WHERE id = $rid LIMIT 1");
        $row = $check->fetch_assoc();
        if (!$row) apiResponse(['success' => false, 'message' => 'Request not found']);

        $isAdmin = ($user['system_role'] === 'Admin' || $user['system_role'] === 'HRM');

        if ($row['user_id'] != $user['id'] && !$isAdmin) {
             apiResponse(['success' => false, 'message' => 'Permission denied']);
        }

        if ($row['status'] !== 'pending' && !$isAdmin) {
             apiResponse(['success' => false, 'message' => 'អាចលុបបានតែសំណើដែលកំពុងរង់ចាំ (Pending)']);
        }

        // Refund leave balance if deleting a pending leave request
        if ($row['request_type'] === 'Leave' && $row['status'] === 'pending' && floatval($row['number_of_days']) > 0) {
            $numDays = floatval($row['number_of_days']);
            $targetUid = (int)$row['user_id'];
            $mysqli->query("UPDATE users SET annual_leave_balance = annual_leave_balance + $numDays WHERE id = $targetUid");
        }

        if ($mysqli->query("DELETE FROM requests WHERE id = $rid")) {
            apiResponse(['success' => true, 'message' => 'លុបសំណើបានជោគជ័យ']);
        } else {
            apiResponse(['success' => false, 'message' => 'Delete failed: ' . $mysqli->error]);
        }
        break;

    case 'approve_request':
        if (!$user) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $rid = (int) ($_POST['id'] ?? 0);
        $status = trim((string) ($_POST['status'] ?? 'approved'));
        $comment = trim((string) ($_POST['admin_comment'] ?? ''));
        $sysRole = (string) ($user['system_role'] ?? 'Employee');

        if (!in_array($sysRole, ['Admin', 'HRM'], true)) {
            apiResponse(['success' => false, 'message' => 'Permission denied. Only Admin/HRM can approve.']);
        }
        if ($rid <= 0 || !in_array($status, ['approved', 'rejected'], true)) {
            apiResponse(['success' => false, 'message' => 'Invalid request parameters']);
        }

        $currentRequest = null;
        if ($stmt = $mysqli->prepare("SELECT r.status, r.request_type, u.employee_id FROM requests r LEFT JOIN users u ON r.user_id = u.id WHERE r.id = ? LIMIT 1")) {
            $stmt->bind_param("i", $rid);
            $stmt->execute();
            $res = $stmt->get_result();
            $currentRequest = $res ? $res->fetch_assoc() : null;
            $stmt->close();
        }
        if (!$currentRequest) {
            apiResponse(['success' => false, 'message' => 'Request not found']);
        }

        $mysqli->query("ALTER TABLE requests ADD COLUMN IF NOT EXISTS admin_comment TEXT DEFAULT NULL");
        $mysqli->query("ALTER TABLE requests ADD COLUMN IF NOT EXISTS approved_by VARCHAR(191) DEFAULT NULL");
        $mysqli->query("ALTER TABLE requests ADD COLUMN IF NOT EXISTS approved_at DATETIME DEFAULT NULL");

        $stmt = $mysqli->prepare("UPDATE requests SET status = ?, admin_comment = ?, approved_by = ?, approved_at = NOW() WHERE id = ?");
        if ($stmt) {
            $approverName = (string) ($user['name'] ?? '');
            $stmt->bind_param("sssi", $status, $comment, $approverName, $rid);
            if ($stmt->execute()) {
                add_request_workflow_log(
                    $mysqli,
                    $rid,
                    $status === 'approved' ? 'approved' : 'rejected',
                    (string) ($currentRequest['status'] ?? ''),
                    $status,
                    (string) ($user['employee_id'] ?? ''),
                    $approverName,
                    $sysRole,
                    $comment !== '' ? $comment : ('Request ' . $status . '.'),
                    ['request_type' => (string) ($currentRequest['request_type'] ?? '')]
                );

                $targetEmployeeId = trim((string) ($currentRequest['employee_id'] ?? ''));
                if ($targetEmployeeId !== '') {
                    $title = $status === 'approved' ? 'Request Approved' : 'Request Rejected';
                    $body = 'Your ' . ((string) ($currentRequest['request_type'] ?? 'request')) . ' request was ' . $status . ' by ' . $approverName;
                    if ($comment !== '') {
                        $body .= ': ' . $comment;
                    }
                    sendAppNotificationToUser($mysqli, $targetEmployeeId, $title, $body);
                }

                apiResponse(['success' => true, 'message' => 'Request ' . ucfirst($status)]);
            } else {
                apiResponse(['success' => false, 'message' => 'Update failed: ' . $mysqli->error]);
            }
            $stmt->close();
        }
        break;

    case 'approve_request_legacy':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $rid     = (int)($_POST['id'] ?? 0);
        $status  = $_POST['status'] ?? 'approved'; // approved or rejected
        $comment = $_POST['admin_comment'] ?? '';
        $sysRole = $user['system_role'] ?? 'Employee';

        if ($sysRole !== 'Admin' && $sysRole !== 'HRM') {
            apiResponse(['success' => false, 'message' => 'Permission denied. Only Admin/HRM can approve.']);
        }

        // Self-heal columns
        $mysqli->query("ALTER TABLE requests ADD COLUMN IF NOT EXISTS admin_comment TEXT DEFAULT NULL");
        $mysqli->query("ALTER TABLE requests ADD COLUMN IF NOT EXISTS approved_by VARCHAR(191) DEFAULT NULL");
        $mysqli->query("ALTER TABLE requests ADD COLUMN IF NOT EXISTS approved_at DATETIME DEFAULT NULL");

        $stmt = $mysqli->prepare("UPDATE requests SET status = ?, admin_comment = ?, approved_by = ?, approved_at = NOW() WHERE id = ?");
        if ($stmt) {
            $stmt->bind_param("sssi", $status, $comment, $user['name'], $rid);
            if ($stmt->execute()) {
                // Notify user about approval/rejection
                $status_kh = ($status === 'approved') ? 'ត្រូវបានអនុម័ត' : 'ត្រូវបានបដិសេធ';
                $title_kh = "សំណើ " . (($status === 'approved') ? 'អនុម័ត' : 'បដិសេធ');

                // Get user employee_id for the request
                $uCheck = $mysqli->query("SELECT u.employee_id, r.request_type FROM requests r JOIN users u ON r.user_id = u.id WHERE r.id = $rid LIMIT 1");
                if ($uRow = $uCheck->fetch_assoc()) {
                    sendAppNotificationToUser($mysqli, $uRow['employee_id'], $title_kh, "សំណើ " . $uRow['request_type'] . " របស់អ្នក " . $status_kh . " ដោយ " . $user['name'] . ($comment ? ": " . $comment : ""));
                }

                apiResponse(['success' => true, 'message' => "Request " . ucfirst($status)]);
            } else {
                apiResponse(['success' => false, 'message' => 'Update failed: ' . $mysqli->error]);
            }
            $stmt->close();
        }
        break;


    case 'submit_attendance':
    case 'checkin':
    case 'checkout':
    case 'Check-In':
    case 'Check-Out':
    case 'check-in':
    case 'check-out':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $eid = $user['employee_id'];
        $uname = $user['name'];
        $action_type = $_POST['action'] ?? $action; // Check-In or Check-Out

        // Debug: Log attendance submission parameters
        $hasPhoto = !empty($_POST['photo_base64']) ? 'YES' : 'NO';
        $wpLog = $_POST['workplace'] ?? 'N/A';
        @file_put_contents(__DIR__ . '/uploads/face_match_debug.log', date('[Y-m-d H:i:s] ') . "Submit Request: EID={$eid} | Name={$uname} | ActionType={$action_type} | Workplace={$wpLog} | HasPhoto={$hasPhoto}\n", FILE_APPEND);
        $loc_id = (int)($_POST['qr_location_id'] ?? 0);
        $qr_secret = trim($_POST['qr_secret'] ?? '');
        $user_loc_raw = trim($_POST['user_location_raw'] ?? '');
        $u_lat = null; $u_lon = null;
        if (!empty($user_loc_raw) && strpos($user_loc_raw, ',') !== false) {
            list($u_lat, $u_lon) = explode(',', $user_loc_raw);
        }
        $late_reason = $_POST['late_reason'] ?? '';

        // Bypass location validation if it's an outside scan
        if ($qr_secret === 'outside_scan' || $loc_id <= 0) {
            $loc_name = !empty($_POST['manual_location_name']) ? trim($_POST['manual_location_name']) : 'Outside';
            $distance_m = 0;
            $status = 'Good';
            if (empty($user_loc_raw)) {
                apiResponse(['success' => false, 'message' => 'មិនអាចទទួលបានទីតាំង GPS របស់អ្នកទេ']);
            }

            // Detect nearest location based on user's current GPS
            if ($u_lat !== null && $u_lon !== null) {
                // Fetch all active/configured locations for this user or general locations
                $loc_sql = "SELECT l.id, l.location_name, l.latitude, l.longitude, 
                                   COALESCE(ul.custom_radius_meters, l.radius_meters) as final_radius
                            FROM locations l
                            LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ?";
                $loc_stmt = $mysqli->prepare($loc_sql);
                if ($loc_stmt) {
                    $loc_stmt->bind_param("s", $eid);
                    $loc_stmt->execute();
                    $loc_res = $loc_stmt->get_result();
                    $closest_loc = null;
                    $min_distance = doubleval(99999999);
                    
                    while ($loc_row = $loc_res->fetch_assoc()) {
                        $dist = haversine_distance($u_lat, $u_lon, $loc_row['latitude'], $loc_row['longitude']);
                        if ($dist < $min_distance) {
                            $min_distance = $dist;
                            $closest_loc = $loc_row;
                        }
                    }
                    $loc_stmt->close();

                    if ($closest_loc !== null) {
                        // If they are within the allowed radius of this location, associate them with it
                        if ($min_distance <= (float)$closest_loc['final_radius']) {
                            $loc_name = $closest_loc['location_name'];
                            $distance_m = $min_distance;
                            $loc_id = (int)$closest_loc['id'];
                        } else {
                            // If they are outside, we still calculate the correct distance to the closest location
                            // instead of reporting 0. We can show Area: "Outside" and Distance: actual distance.
                            $distance_m = $min_distance;
                        }
                    }
                }
            }
        } else {
            // 1. Validate QR & Location
            $sql = "SELECT l.*, COALESCE(ul.custom_radius_meters, l.radius_meters) as final_radius
                    FROM locations l
                    LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ?
                    WHERE l.id = ? LIMIT 1";
            $stmt = $mysqli->prepare($sql);
            $loc_data = null;
            if ($stmt) {
                $stmt->bind_param("si", $eid, $loc_id);
                $stmt->execute();
                $loc_data = $stmt->get_result()->fetch_assoc();
                $stmt->close();
            }

            if (!$loc_data) apiResponse(['success' => false, 'message' => 'រកមិនឃើញទីតាំងនេះទេ']);

            // 2. Secret Key Check
            if ($loc_data['qr_secret'] !== $qr_secret) {
                apiResponse(['success' => false, 'message' => 'QR Code មិនត្រឹមត្រូវ']);
            }

            // 3. Geo-fencing
            $distance_m = 0;
            $status = 'Good';
            if ($u_lat !== null && $u_lon !== null) {
                $distance_m = haversine_distance($u_lat, $u_lon, $loc_data['latitude'], $loc_data['longitude']);
                if ($distance_m > (float)$loc_data['final_radius']) {
                    $status = 'Too Far';
                    apiResponse(['success' => false, 'message' => 'អ្នកនៅឆ្ងាយពីទីតាំងពេក (' . round($distance_m) . 'm)']);
                }
            } else {
                apiResponse(['success' => false, 'message' => 'មិនអាចទទួលបានទីតាំង GPS របស់អ្នកទេ']);
            }
            $loc_name = $loc_data['location_name'];
        }

        // 4. Attendance Rules (Late/Good/Absent)
        $current_time = date('H:i:s');
        $rule_type = (stripos($action_type, 'in') !== false) ? 'checkin' : 'checkout';
        $rule_stmt = $mysqli->prepare("SELECT status FROM attendance_rules WHERE employee_id = ? AND type = ? AND start_time <= ? AND end_time >= ? LIMIT 1");
        if ($rule_stmt) {
            $rule_stmt->bind_param("ssss", $eid, $rule_type, $current_time, $current_time);
            $rule_stmt->execute();
            $rule_res = $rule_stmt->get_result()->fetch_assoc();
            if ($rule_res) $status = $rule_res['status'];
            $rule_stmt->close();
        }

        // --- NEW: Check if >= 15 mins late and reason is missing ---
        if ($status === 'Late' && empty($late_reason)) {
            $good_stmt = $mysqli->prepare("SELECT end_time FROM attendance_rules WHERE employee_id = ? AND type = ? AND status = 'Good' AND end_time <= ? ORDER BY end_time DESC LIMIT 1");
            if ($good_stmt) {
                $good_stmt->bind_param("sss", $eid, $rule_type, $current_time);
                $good_stmt->execute();
                $good_res = $good_stmt->get_result()->fetch_assoc();
                if ($good_res) {
                    $expected_time = $good_res['end_time'];
                    $diff_minutes = round((strtotime($current_time) - strtotime($expected_time)) / 60);
                    if ($diff_minutes >= 15) {
                        apiResponse([
                            'success' => false,
                            'require_late_reason' => true,
                            'message' => 'អ្នកបានស្កេនចូលយឺតជាងពេលកំណត់ (' . $diff_minutes . ' នាទី)។ សូមបំពេញមូលហេតុនៃការយឺតយ៉ាវនេះ!'
                        ]);
                    }
                }
                $good_stmt->close();
            }
        }

        // 4.5. Verify Face Scan if applicable (both Face Scan inside office and Outside check-in)
        $wp = trim($_POST['workplace'] ?? '');
        if ($wp === 'Face Scan' || $wp === 'Outside') {
            $check_photo_b64 = trim($_POST['photo_base64'] ?? '');
            if (empty($check_photo_b64)) {
                apiResponse([
                    'success' => false,
                    'message' => 'រកមិនឃើញរូបថតស្កេនផ្ទៃមុខ ឬទិន្នន័យរូបថតត្រូវបានបដិសេធដោយ Server (ទំហំធំពេក)។ សូមប្រាកដថាអ្នកបានដំឡើងកម្មវិធីទូរស័ព្ទចុងក្រោយបង្អស់!'
                ]);
            }
            
            // Check if biometric verification was completed on the device (Face ID / Touch ID)
            $biometric_verified = ($_POST['biometric_verified'] ?? '') === '1' || ($_POST['biometric_verified'] ?? '') === 'true';
            
            if (!$biometric_verified) {
                // Fallback to server-side AI matching for older app versions
                $faceVerification = ai_verify_face_match($mysqli, $eid, $check_photo_b64);
                if (!($faceVerification['match'] ?? false)) {
                    apiResponse(['success' => false, 'message' => $faceVerification['message'] ?? 'ការផ្ទៀងផ្ទាត់ផ្ទៃមុខមិនត្រូវគ្នាទេ!']);
                }
            }
        }

        // 5. Process Photo Upload
        $photo_base64 = $_POST['photo_base64'] ?? '';
        $photo_path = null;
        if (!empty($photo_base64)) {
            $photo_dir = __DIR__ . '/uploads/checkins/';
            if (!is_dir($photo_dir)) {
                mkdir($photo_dir, 0777, true);
            }
            $photo_name = 'checkin_' . $eid . '_' . time() . '.jpg';
            $file_path = $photo_dir . $photo_name;
            if (file_put_contents($file_path, base64_decode($photo_base64))) {
                $photo_path = 'uploads/checkins/' . $photo_name;
            }
        }

        // 6. Save Log
        $ins = $mysqli->prepare("INSERT INTO checkin_logs (
            employee_id, name, action_type, log_datetime, status,
            location_name, distance_m, late_reason, photo_path, latitude, longitude, qr_location_id, geo_address
        ) VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?, ?, ?, ?, ?)");

        if ($ins) {
            $u_lat = isset($u_lat) ? floatval($u_lat) : null;
            $u_lon = isset($u_lon) ? floatval($u_lon) : null;
            $geo_address = get_address_from_gps($u_lat, $u_lon);

            $ins->bind_param("sssssdssddis", $eid, $uname, $action_type, $status, $loc_name, $distance_m, $late_reason, $photo_path, $u_lat, $u_lon, $loc_id, $geo_address);
            if ($ins->execute()) {
                // Telegram Notification
                sendAttendanceTelegram($mysqli, $eid, [
                    'name' => $uname,
                    'action' => $action_type,
                    'status' => $status,
                    'location_name' => $loc_name,
                    'distance_m' => $distance_m,
                    'late_reason' => $late_reason
                ]);

                // HR App Notification (Always for every scan)
                sendAppNotificationToRoles($mysqli, ['HRM', 'Admin'], 'វត្តមានថ្មី: ' . $action_type, "បុគ្គលិក {$uname} ({$eid}) បាន " . strtoupper($action_type) . " នៅ " . htmlspecialchars($loc_name) . " ({$status})");

                apiResponse(['success' => true, 'message' => "ស្កេនបានជោគជ័យ ($status)"]);
            } else {
                error_log("Attendance Submit Error: " . $mysqli->error);
                apiResponse(['success' => false, 'message' => 'Database error: ' . $mysqli->error]);
            }
            $ins->close();
        }
        break;

    // --------------------------------------------------------
    // NOTIFICATIONS
    // --------------------------------------------------------
    case 'send_notification':
    case 'get_user_notifications':
    case 'mark_notification_read':
        // No need to ensure tables here as they are checked at API init
        // Continue matching the specific action
        if ($action === 'send_notification') {
            if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
            $title = $_POST['notification_title'] ?? '';
            $msg = $_POST['notification_message'] ?? '';
            $type = $_POST['recipient_type'] ?? 'all';
            $expiry = $_POST['expiry_date'] ?? null;
            if ($expiry) $expiry = substr($expiry, 0, 10); // Clean ISO string

            if (!$title || !$msg) apiResponse(['status' => 'error', 'message' => 'Title and Message required']);

            $stmt = $mysqli->prepare("INSERT INTO notifications (admin_id, title, message, recipient_type, expiry_date) VALUES (?, ?, ?, ?, ?)");
            $stmt->bind_param("sssss", $user['employee_id'], $title, $msg, $type, $expiry);
            if ($stmt->execute()) {
                $nid = $mysqli->insert_id;
                if ($type === 'all') {
                    $mysqli->query("INSERT INTO user_notifications (notification_id, employee_id)
                                   SELECT $nid, employee_id FROM users");
                }
                apiResponse(['status' => 'success', 'message' => 'Notification sent successfully']);
            } else {
                apiResponse(['status' => 'error', 'message' => 'DB Error: ' . $mysqli->error]);
            }
        }

        if ($action === 'get_user_notifications') {
            if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
            $eid = $user['employee_id'];
            $uid = (int)$user['id'];
            $sysRole = $user['system_role'] ?? 'Employee';

            $data = [];

            // 1. Fetch manual notifications
            $sql = "SELECT n.id, n.title, n.message, n.image_url, DATE_FORMAT(n.sent_at, '%d/%m/%Y %h:%i %p') as created_at,
                           COALESCE(un.is_read, 0) as is_read, 'general' as type, 0 as target_id
                    FROM user_notifications un
                    JOIN notifications n ON un.notification_id = n.id
                    WHERE un.employee_id = ?
                    ORDER BY un.notification_id DESC LIMIT 30";
            $stmt = $mysqli->prepare($sql);
            if ($stmt) {
                $stmt->bind_param("s", $eid);
                $stmt->execute();
                $res = $stmt->get_result();
                while ($row = $res->fetch_assoc()) {
                    if (strpos($row['title'], 'ដំណើរ') !== false || strpos($row['title'], '🚗') !== false) {
                        $row['type'] = 'gps_tracking';
                        if (preg_match('/#(\d+)/', $row['message'], $matches)) {
                            $row['target_id'] = (int)$matches[1];
                        }
                    }
                    $data[] = $row;
                }
                $stmt->close();
            }

            // 2. Fetch Requests as Notifications
            if ($sysRole === 'Admin' || $sysRole === 'HRM') {
                // For Admins/HRM: Show pending requests as notifications
                $sqlReq = "SELECT id as target_id, CONCAT('សំណើថ្មីពី: ', requester_name) as title,
                                  CONCAT('ប្រភេទ: ', request_type, ' - ', SUBSTRING(reason, 1, 50)) as message,
                                  created_at, 0 as is_read, 'request' as type, id
                           FROM requests
                           WHERE status = 'pending'
                           ORDER BY id DESC LIMIT 20";
                $resReq = $mysqli->query($sqlReq);
                while ($row = $resReq->fetch_assoc()) {
                    // Prepend requests to give them priority
                    array_unshift($data, $row);
                }
            } else {
                // For regular users: Show status changes of their requests in last 7 days
                $sqlReq = "SELECT id as target_id, CONCAT('សេចក្តីសម្រេចលើ: ', request_type) as title,
                                  CONCAT('ស្ថានភាពសំណើរបស់អ្នកគឺ: ',
                                         CASE WHEN status='approved' THEN 'អនុម័ត'
                                              WHEN status='rejected' THEN 'បដិសេធ'
                                              ELSE status END) as message,
                                  updated_at as created_at, 1 as is_read, 'request_status' as type, id
                           FROM requests
                           WHERE (user_id = ? OR requester_name = ?)
                             AND status IN ('approved', 'rejected')
                             AND updated_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                           ORDER BY updated_at DESC LIMIT 10";
                $stmtReq = $mysqli->prepare($sqlReq);
                if ($stmtReq) {
                    $uname = $user['name'] ?? '';
                    $stmtReq->bind_param("is", $uid, $uname);
                    $stmtReq->execute();
                    $resReq = $stmtReq->get_result();
                    while ($row = $resReq->fetch_assoc()) { $data[] = $row; }
                    $stmtReq->close();
                }
            }

            // Sort consolidated list by date
            usort($data, function($a, $b) {
                return strtotime($b['created_at']) - strtotime($a['created_at']);
            });

            // Automatically mark all general notifications as read to clear the home screen badge when viewed
            // (Note: The response data still returns them with their original is_read status so they highlight as new)
            $mysqli->query("UPDATE user_notifications SET is_read = 1, read_at = NOW() WHERE employee_id = '$eid' AND is_read = 0");

            apiResponse(['status' => 'success', 'success' => true, 'notifications' => $data, 'data' => $data]);
        }

        if ($action === 'mark_notification_read') {
            $nid = (int)($_POST['notification_id'] ?? 0);
            if (!$user || !$nid) apiResponse(['status' => 'error', 'message' => 'Invalid request']);
            $res = $mysqli->query("UPDATE user_notifications SET is_read = 1, read_at = NOW() WHERE notification_id = $nid AND employee_id = '{$user['employee_id']}'");
            if ($res) {
                apiResponse(['status' => 'success', 'message' => 'Marked as read']);
            } else {
                apiResponse(['status' => 'error', 'message' => 'Database error: ' . $mysqli->error]);
            }
        }
        break;

    case 'get_announcements':
        // Fetch active banners from the dedicated announcements table
        $res = $mysqli->query("SELECT id, title, text, image_url, external_link FROM announcements WHERE is_active = 1 ORDER BY order_index ASC, id DESC LIMIT 5");
        $items = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $items[] = $row;
            }
        }
        apiResponse(['success' => true, 'data' => $items]);
        break;



    case 'get_checklist':
        if (!$user) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Unauthorized']);
        $eid = $user['employee_id'];
        $stmt = $mysqli->prepare("SELECT *, DATE_FORMAT(created_at, '%d/%m/%Y %h:%i %p') as created_at_formatted FROM work_checklist WHERE admin_id = ? OR user_id = ? ORDER BY created_at DESC");
        $stmt->bind_param("ss", $eid, $eid);
        $stmt->execute();
        $res = $stmt->get_result();
        $data = [];
        // Base URL logic for full image URLs
        $proto = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http';
        $host = $_SERVER['HTTP_HOST'] ?? 'app.vvc.asia';
        $self = $_SERVER['PHP_SELF'] ?? '/api.php';
        $baseDir = str_replace('api.php', '', $self);
        $baseUrl = "$proto://$host$baseDir";

        while ($row = $res->fetch_assoc()) {
            if (!empty($row['image_path'])) {
                $row['image_url'] = $baseUrl . $row['image_path'];
            }
            $data[] = $row;
        }
        apiResponse(['success' => true, 'status' => 'success', 'data' => $data]);
        break;

    case 'add_checklist_item':
        if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
        $task = $_POST['task'] ?? '';
        $category = $_POST['category'] ?? 'General';
        $sdate = $_POST['start_date'] ?? null;
        $stime = $_POST['start_time'] ?? null;
        $edate = $_POST['end_date'] ?? null;
        $etime = $_POST['end_time'] ?? null;
        $image_base64 = $_POST['image_base64'] ?? '';

        if (!$task) apiResponse(['status' => 'error', 'message' => 'Task is required']);
        $eid = $user['employee_id'];

        $image_path = null;
        if (!empty($image_base64)) {
            $dir = __DIR__ . '/uploads/checklist/';
            if (!is_dir($dir) && !@mkdir($dir, 0777, true)) {
                 apiResponse(['status' => 'error', 'message' => 'Failed to create uploads directory']);
            }
            $fname = 'task_' . time() . '_' . rand(1000, 9999) . '.jpg';
            if (file_put_contents($dir . $fname, base64_decode($image_base64))) {
                $image_path = 'uploads/checklist/' . $fname;
            } else {
                 apiResponse(['status' => 'error', 'message' => 'Failed to save image file']);
            }
        }

        $stmt = $mysqli->prepare("INSERT INTO work_checklist (admin_id, task, category, start_date, start_time, end_date, end_time, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bind_param("ssssssss", $eid, $task, $category, $sdate, $stime, $edate, $etime, $image_path);
        if ($stmt->execute()) {
            apiResponse(['status' => 'success', 'message' => 'Task added']);
        } else {
            apiResponse(['status' => 'error', 'message' => 'Failed to add task: ' . $mysqli->error]);
        }
        break;

    case 'toggle_checklist_status':
        $tid = (int)($_POST['task_id'] ?? 0);
        $status = ($_POST['status'] ?? '') === 'completed' ? 1 : 0;
        if (!$tid) apiResponse(['status' => 'error', 'message' => 'Invalid task ID']);
        $mysqli->query("UPDATE work_checklist SET is_done = $status WHERE id = $tid");
        apiResponse(['status' => 'success', 'message' => 'Status updated']);
        break;

    case 'delete_checklist_item':
        if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
        $tid = (int)($_POST['task_id'] ?? 0);
        if (!$tid) apiResponse(['status' => 'error', 'message' => 'Invalid task ID']);
        $eid = $user['employee_id'];
        $stmt = $mysqli->prepare("DELETE FROM work_checklist WHERE id = ? AND (admin_id = ? OR user_id = ?)");
        $stmt->bind_param("iss", $tid, $eid, $eid);
        if ($stmt->execute()) {
            apiResponse(['status' => 'success', 'message' => 'Task deleted']);
        } else {
            apiResponse(['status' => 'error', 'message' => 'Failed to delete task']);
        }
        break;

    case 'edit_checklist_item':
        if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
        $tid = (int)($_POST['task_id'] ?? 0);
        $task = $_POST['task'] ?? '';
        $category = $_POST['category'] ?? 'General';
        $sdate = $_POST['start_date'] ?? null;
        $stime = $_POST['start_time'] ?? null;
        $edate = $_POST['end_date'] ?? null;
        $etime = $_POST['end_time'] ?? null;
        $image_base64 = $_POST['image_base64'] ?? '';

        if (!$tid || !$task) apiResponse(['status' => 'error', 'message' => 'Task ID and Description are required']);
        $eid = $user['employee_id'];

        $image_sql = "";
        if (!empty($image_base64)) {
            $dir = __DIR__ . '/uploads/checklist/';
            if (!is_dir($dir)) mkdir($dir, 0777, true);
            $fname = 'task_' . time() . '_' . rand(1000, 9999) . '.jpg';
            if (file_put_contents($dir . $fname, base64_decode($image_base64))) {
                $image_path = 'uploads/checklist/' . $fname;
                $image_sql = ", image_path = '$image_path'";
            }
        }

        $stmt = $mysqli->prepare("UPDATE work_checklist SET task = ?, category = ?, start_date = ?, start_time = ?, end_date = ?, end_time = ? $image_sql WHERE id = ? AND (admin_id = ? OR user_id = ?)");
        $stmt->bind_param("sssssiss", $task, $category, $sdate, $stime, $edate, $etime, $tid, $eid, $eid);
        if ($stmt->execute()) {
            apiResponse(['status' => 'success', 'message' => 'Task updated']);
        } else {
            apiResponse(['status' => 'error', 'message' => 'Failed to update task: ' . $mysqli->error]);
        }
        break;

    case 'get_report_positions':
        // Get positions that have Telegram Topic mappings configured
        $positions = [];

        // Query HRM database if available
        $hrm_db = getHRMConnection();
        $db_to_use = $hrm_db ?: $mysqli;

        $query = "SELECT DISTINCT
                    COALESCE(NULLIF(tgt.position, ''), NULLIF(tgt.category, ''), tg.name) as position_name,
                    tgt.thread_id,
                    tg.chat_id,
                    tgt.id as mapping_id
                  FROM telegram_group_threads tgt
                  JOIN telegram_groups tg ON tgt.group_id = tg.id
                  WHERE tgt.thread_id IS NOT NULL
                    AND tgt.thread_id != ''
                    AND (tgt.position IS NOT NULL OR tgt.category IS NOT NULL)
                  ORDER BY position_name ASC";

        $result = $db_to_use->query($query);
        if ($result) {
            while ($row = $result->fetch_assoc()) {
                if (!empty($row['position_name'])) {
                    $positions[] = [
                        'name' => $row['position_name'],
                        'thread_id' => $row['thread_id'],
                        'chat_id' => $row['chat_id'],
                        'mapping_id' => $row['mapping_id']
                    ];
                }
            }
        }
        if ($hrm_db) $hrm_db->close();

        // If no positions found in telegram_group_threads, fall back to user's own position
        if (empty($positions) && $user) {
            $user_pos = $user['position'] ?? '';
            if (!empty($user_pos)) {
                $positions[] = [
                    'name' => $user_pos,
                    'thread_id' => null,
                    'chat_id' => null,
                    'mapping_id' => null
                ];
            }
        }

        apiResponse([
            'success' => true,
            'positions' => $positions,
            'count' => count($positions)
        ]);
        break;

    case 'submit_daily_report':
        if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
        $content = $_POST['content'] ?? '';
        $position = $_POST['position'] ?? '';
        // Accept direct thread_id and chat_id from app (avoids charset matching issues)
        $direct_thread_id = $_POST['thread_id'] ?? '';
        $direct_chat_id   = $_POST['chat_id'] ?? '';
        if (!$content) apiResponse(['status' => 'error', 'message' => 'Content is required']);
        $eid = $user['employee_id'];
        $date = date('Y-m-d');

        // Optional: add position column to daily_reports if missing (Compatible way)
        $col_check_dr = $mysqli->query("SHOW COLUMNS FROM daily_reports LIKE 'position'");
        if ($col_check_dr && $col_check_dr->num_rows === 0) {
            $mysqli->query("ALTER TABLE daily_reports ADD COLUMN position VARCHAR(100) AFTER user_id");
        }

        $stmt = $mysqli->prepare("INSERT INTO daily_reports (user_id, position, report_date, content) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("ssss", $eid, $position, $date, $content);
        if ($stmt->execute()) {
            // Auto-ensure Telegram setting is enabled for Daily Reports if missing or disabled
            $mysqli->query("INSERT INTO daily_report_telegram_settings (id, enabled) VALUES (1, 1) ON DUPLICATE KEY UPDATE enabled = 1");

            // App Notification for Admin and HRM
            $reporter_name = trim((string)($user['name'] ?? ''));
            if ($reporter_name === '') $reporter_name = $eid;
            $position_note = trim((string)$position) !== '' ? " • " . trim((string)$position) : "";
            $report_preview_raw = preg_replace('/\s+/u', ' ', strip_tags($content));
            if ($report_preview_raw === null) {
                $report_preview_raw = strip_tags($content);
            }
            $report_preview = trim($report_preview_raw);
            if (function_exists('mb_strlen') && function_exists('mb_substr')) {
                if (mb_strlen($report_preview, 'UTF-8') > 120) {
                    $report_preview = mb_substr($report_preview, 0, 120, 'UTF-8') . '...';
                }
            } elseif (strlen($report_preview) > 120) {
                $report_preview = substr($report_preview, 0, 120) . '...';
            }
            $notify_message = "បុគ្គលិក " . $reporter_name . " (" . $eid . ") បានបញ្ចូលរបាយការណ៍ប្រចាំថ្ងៃ ថ្ងៃទី " . date('d/m/Y') . $position_note . "។";
            if ($report_preview !== '') {
                $notify_message .= "\n\n" . $report_preview;
            }
            sendAppNotificationToRoles(
                $mysqli,
                ['Admin', 'HRM'],
                "របាយការណ៍ប្រចាំថ្ងៃថ្មី",
                $notify_message,
                $eid,
                null,
                null,
                [
                    'type' => 'daily_report',
                    'employee_id' => $eid,
                    'priority' => 'high',
                    'channel_id' => 'vvc_hrm_channel'
                ]
            );

            // Send to Telegram if configured
            if (function_exists('sendDailyReportToTelegram')) {
                sendDailyReportToTelegram(
                    $mysqli, $eid, $user['name'], $position, $content, $date,
                    $direct_thread_id ?: null,
                    $direct_chat_id ?: null
                );
            }

            apiResponse(['status' => 'success', 'message' => 'Report submitted']);
        } else {
            apiResponse(['status' => 'error', 'message' => 'Failed to submit report: ' . $mysqli->error]);
        }
        break;
    case 'get_all_daily_reports':
        if (!$user) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Unauthorized']);
        $isAdmin = (strcasecmp($user['system_role'], 'Admin') === 0 || strcasecmp($user['system_role'], 'HRM') === 0);
        if (!$isAdmin) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Permission denied']);

        $sql = "SELECT r.id, r.user_id, r.position, r.content,
                       r.report_date as raw_date,
                       DATE_FORMAT(r.report_date, '%d/%m/%Y') as report_date,
                       MIN(u.name) as user_name, MAX(u.avatar) as avatar
                FROM daily_reports r
                LEFT JOIN users u ON r.user_id = u.employee_id
                GROUP BY r.id
                ORDER BY r.report_date DESC, r.id DESC LIMIT 500";

        $res = $mysqli->query($sql);
        $data = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $data[] = $row;
            }
        } else {
             apiResponse(['success' => false, 'message' => 'Query Failed: ' . $mysqli->error]);
        }
        apiResponse(['success' => true, 'status' => 'success', 'data' => $data]);
        break;

    case 'get_my_daily_reports':
        if (!$user) apiResponse(['success' => false, 'status' => 'error', 'message' => 'Unauthorized']);
        $eid = $user['employee_id'];

        // Use a simpler query first to check if it's a data issue or syntax issue
        $sql = "SELECT id, user_id, position, content,
                       report_date as raw_date,
                       DATE_FORMAT(report_date, '%d/%m/%Y') as report_date
                FROM daily_reports
                WHERE user_id = ?
                ORDER BY id DESC LIMIT 50";

        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
             apiResponse(['success' => false, 'message' => 'Query Prepare Failed: ' . $mysqli->error]);
        }
        $stmt->bind_param("s", $eid);
        $stmt->execute();
        $res = $stmt->get_result();
        $data = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $data[] = $row;
            }
        }
        apiResponse(['success' => true, 'status' => 'success', 'data' => $data]);
        break;

    case 'submit_mission_letter':
        if (!$user) apiResponse(['status' => 'error', 'message' => 'Unauthorized']);
        $location  = trim($_POST['location']  ?? '');
        $purpose   = trim($_POST['purpose']   ?? '');
        $sdate     = trim($_POST['start_date'] ?? '');
        $stime     = trim($_POST['start_time'] ?? '');
        $edate     = trim($_POST['end_date']   ?? '');
        $etime     = trim($_POST['end_time']   ?? '');
        $transport = trim($_POST['transport']  ?? '');
        $materials = trim($_POST['materials']  ?? '');
        $dk_part1  = trim($_POST['date_khmer_part1'] ?? '');
        $dk_part2  = trim($_POST['date_khmer_part2'] ?? '');
        $date_khmer = $dk_part1 . 'br' . $dk_part2;
        $personnel_json = $_POST['personnel_json'] ?? '';
        $personnel_rows = [];
        if (!empty($personnel_json)) {
            $decoded_personnel = json_decode($personnel_json, true);
            if (is_array($decoded_personnel)) {
                $personnel_rows = $decoded_personnel;
            }
        }

        if (!$location || !$sdate) apiResponse(['status' => 'error', 'message' => 'Missing fields']);
        $eid = $user['employee_id'];

        // Build dynamic INSERT
        $cols   = ['employee_id','location','purpose','start_date','start_time','end_date','end_time','transport','materials','date_khmer'];
        $vals   = [$eid, $location, $purpose, $sdate, $stime, $edate, $etime, $transport, $materials, $date_khmer];
        $types  = 'ssssssssss';

        for ($pi = 1; $pi <= 10; $pi++) {
            $pname = trim($_POST["person{$pi}"] ?? '');
            $prole = trim($_POST["role{$pi}"] ?? '');
            if ($pname === '' && isset($personnel_rows[$pi - 1]) && is_array($personnel_rows[$pi - 1])) {
                $pname = trim((string)($personnel_rows[$pi - 1]['name'] ?? ''));
                $prole = trim((string)($personnel_rows[$pi - 1]['role'] ?? ''));
            }
            if ($pname !== '') {
                $cols[]  = "person{$pi}";
                $cols[]  = "role{$pi}";
                $vals[]  = $pname;
                $vals[]  = $prole;
                $types  .= 'ss';
            }
        }

        $placeholders = implode(',', array_fill(0, count($cols), '?'));
        $col_str = implode(',', $cols);
        $stmt = $mysqli->prepare("INSERT INTO mission_letters ($col_str) VALUES ($placeholders)");
        $stmt->bind_param($types, ...$vals);

        if ($stmt->execute()) {
            // Notification for Admin and HRM
            sendAppNotificationToRoles($mysqli, ['Admin', 'HRM'], 'លិខិតបេសកកម្មថ្មី', 'មានលិខិតបេសកកម្មថ្មីទៅកាន់ ' . $location . ' ពី ' . $user['name'] . ' (' . $eid . ') បានដាក់ជូនហើយ។');

            // Send to Telegram
            sendMissionTelegram($mysqli, $eid, [
                'name' => $user['name'],
                'location' => $location,
                'purpose' => $purpose,
                'start_date' => $sdate,
                'end_date' => $edate,
                'start_time' => $stime,
                'end_time' => $etime,
                'transport' => $transport,
                'materials' => $materials
            ]);

            apiResponse(['status' => 'success', 'message' => 'Mission letter submitted']);
        } else {
            apiResponse(['status' => 'error', 'message' => 'Failed: ' . $mysqli->error]);
        }
        break;

    case 'get_dept_heads':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $creator_id = $user['id'];

        // Ensure table exists
        $mysqli->query("CREATE TABLE IF NOT EXISTS user_custom_heads (
            id INT AUTO_INCREMENT PRIMARY KEY,
            full_name VARCHAR(255) NOT NULL,
            creator_id INT NOT NULL,
            signature LONGTEXT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        $stmt = $mysqli->prepare("SELECT id, full_name, signature FROM user_custom_heads WHERE creator_id = ? ORDER BY full_name ASC");
        $stmt->bind_param("i", $creator_id);
        $stmt->execute();
        $res = $stmt->get_result();
        $data = [];
        while ($row = $res->fetch_assoc()) { $data[] = $row; }
        apiResponse(['success' => true, 'data' => $data]);
        break;

    case 'get_users':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $isAdmin = strcasecmp($user['system_role'] ?? '', 'Admin') === 0 || strcasecmp($user['system_role'] ?? '', 'HRM') === 0;

        if ($isAdmin) {
            // Admins get full user list (for user management)
            $sql = "SELECT * FROM users ORDER BY name ASC";
        } else {
            // Regular users get only safe public fields (for Chat, etc.)
            $sql = "SELECT employee_id, name, position, department, branch, avatar, user_role, system_role
                    FROM users
                    WHERE (employment_status IS NULL OR employment_status != 'Resigned')
                    ORDER BY name ASC";
        }

        $res = $mysqli->query($sql);
        $data = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $systemRoleValue = $row['system_role'] ?? ($row['user_role'] ?? '');
                $row['role'] = $systemRoleValue;
                if (empty($row['system_role_label'])) {
                    $row['system_role_label'] = function_exists('app_system_role_label') ? app_system_role_label($systemRoleValue) : $systemRoleValue;
                }
                // Always remove sensitive fields for non-admins
                if (!$isAdmin) {
                    unset($row['password'], $row['fcm_token'], $row['auth_token'], $row['base_salary'], $row['nssf_id']);
                }
                $data[] = $row;
            }
            apiResponse(['success' => true, 'data' => $data, 'users' => $data]);
        } else {
            apiResponse(['success' => false, 'message' => 'SQL Error: ' . $mysqli->error]);
        }
        break;

    case 'save_user':
        if (!$user || !(strcasecmp($user['system_role'], 'Admin') === 0 || strcasecmp($user['system_role'], 'HRM') === 0)) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $target_eid = trim($_POST['target_employee_id'] ?? ($_POST['employee_id'] ?? ''));
        $name = trim($_POST['name'] ?? '');
        $pass = $_POST['password'] ?? '';
        $sRole = $_POST['system_role'] ?? 'Employee';
        $sRoleLabel = $_POST['system_role_label'] ?? '';
        $dept = $_POST['department'] ?? '';
        $pos = $_POST['position'] ?? '';
        $branch = $_POST['branch'] ?? '';

        // HR Full Info Fields
        $latin_name = trim($_POST['latin_name'] ?? '');
        $username = trim($_POST['username'] ?? '');
        $email = trim($_POST['email'] ?? '');
        $address = trim($_POST['current_address'] ?? '');
        $joined_at = trim($_POST['joined_at'] ?? null);
        $marital = trim($_POST['marital_status'] ?? 'Single');
        $base_salary = floatval($_POST['base_salary'] ?? 0.0);
        $nssf_id = trim($_POST['nssf_id'] ?? '');

        if (!$target_eid || !$name) apiResponse(['success' => false, 'message' => 'Employee ID and Name are required']);

        $checkStmt = $mysqli->prepare("SELECT employee_id FROM users WHERE employee_id = ?");
        $checkStmt->bind_param("s", $target_eid);
        $checkStmt->execute();
        $exists = $checkStmt->get_result()->fetch_assoc();
        $checkStmt->close();

        $pass_hash = !empty($pass) ? password_hash($pass, PASSWORD_DEFAULT) : null;

        if ($exists) {
            // Update
            $sql = "UPDATE users SET
                    name = ?, system_role = ?, system_role_label = ?,
                    department = ?, position = ?, branch = ?,
                    latin_name = ?, username = ?, email = ?,
                    current_address = ?, joined_at = ?, marital_status = ?,
                    base_salary = ?, nssf_id = ?";

            if ($pass_hash) $sql .= ", password = ?";
            $sql .= " WHERE employee_id = ?";

            $stmt = $mysqli->prepare($sql);
            if ($pass_hash) {
                $stmt->bind_param("sssssssssssssdss",
                    $name, $sRole, $sRoleLabel,
                    $dept, $pos, $branch,
                    $latin_name, $username, $email,
                    $address, $joined_at, $marital,
                    $base_salary, $nssf_id,
                    $pass_hash, $target_eid
                );
            } else {
                $stmt->bind_param("sssssssssssssds",
                    $name, $sRole, $sRoleLabel,
                    $dept, $pos, $branch,
                    $latin_name, $username, $email,
                    $address, $joined_at, $marital,
                    $base_salary, $nssf_id,
                    $target_eid
                );
            }
        } else {
            // Insert
            if (!$pass_hash) $pass_hash = password_hash('123456', PASSWORD_DEFAULT);
            $sql = "INSERT INTO users (
                    employee_id, name, password, system_role, system_role_label,
                    department, position, branch, latin_name, username,
                    email, current_address, joined_at, marital_status,
                    base_salary, nssf_id
                  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            $stmt = $mysqli->prepare($sql);
            $stmt->bind_param("ssssssssssssssds",
                $target_eid, $name, $pass_hash, $sRole, $sRoleLabel,
                $dept, $pos, $branch, $latin_name, $username,
                $email, $address, $joined_at, $marital,
                $base_salary, $nssf_id
            );
        }

        if ($stmt && $stmt->execute()) {
            $stmt->close();
            apiResponse(['success' => true, 'message' => 'User saved successfully']);
        } else {
            $err = $mysqli->error;
            apiResponse(['success' => false, 'message' => "DB Error: $err"]);
        }
        break;

    case 'delete_user':
        if (!$user || !($user['system_role'] === 'Admin' || $user['system_role'] === 'HRM')) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $target_eid = trim($_POST['target_employee_id'] ?? ($_POST['employee_id'] ?? ''));
        if (!$target_eid) apiResponse(['success' => false, 'message' => 'Missing employee ID']);
        if ($target_eid === $user['employee_id']) apiResponse(['success' => false, 'message' => 'Cannot delete yourself']);

        $stmt = $mysqli->prepare("DELETE FROM users WHERE employee_id = ?");
        $stmt->bind_param("s", $target_eid);
        if ($stmt->execute()) {
            apiResponse(['success' => true, 'message' => 'User deleted successfully']);
        } else {
            apiResponse(['success' => false, 'message' => 'Delete failed: ' . $mysqli->error]);
        }
        break;

    case 'debug_test_logs':
        $sql = "SELECT * FROM checkin_logs ORDER BY id DESC LIMIT 5";
        $res = $mysqli->query($sql);
        $data = [];
        if ($res) while($r = $res->fetch_assoc()) $data[] = $r;
        apiResponse(['success' => true, 'data' => $data, 'server_time' => date('Y-m-d H:i:s')]);
        break;

    case 'get_all_attendance_logs':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $isAdmin = (strcasecmp($user['system_role'], 'Admin') === 0 || strcasecmp($user['system_role'], 'HRM') === 0);
        $eid = $user['employee_id'];

        $sql = "SELECT l.id, l.employee_id, l.action_type, l.status, l.location_name, l.distance_m, l.late_reason, l.photo_path,
                       l.latitude, l.longitude, l.qr_location_id, l.geo_address,
                       DATE_FORMAT(l.log_datetime, '%d/%m/%Y %h:%i %p') as log_datetime,
                       u.name as user_name, u.department as user_dept, u.system_role, u.avatar
                FROM checkin_logs l
                LEFT JOIN users u ON l.employee_id = u.employee_id
                WHERE 1=1 ";

        // If not admin, only show their own logs
        if (!$isAdmin) {
            $sql .= " AND l.employee_id = '" . $mysqli->real_escape_string($eid) . "' ";
        }

        // Date range filter
        $start_date = isset($_POST['start_date']) ? trim($_POST['start_date']) : '';
        $end_date   = isset($_POST['end_date'])   ? trim($_POST['end_date'])   : '';

        if (!empty($start_date) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $start_date)) {
            $sql .= " AND DATE(l.log_datetime) >= '" . $mysqli->real_escape_string($start_date) . "' ";
        }
        if (!empty($end_date) && preg_match('/^\d{4}-\d{2}-\d{2}$/', $end_date)) {
            $sql .= " AND DATE(l.log_datetime) <= '" . $mysqli->real_escape_string($end_date) . "' ";
        }

        $limit  = max(1, min(100, (int)($_POST['limit']  ?? 20)));
        $offset = max(0, (int)($_POST['offset'] ?? 0));

        $sql .= " ORDER BY l.log_datetime DESC LIMIT $limit OFFSET $offset";

        $res = $mysqli->query($sql);
        $data = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $data[] = $row;
            }
        }
        apiResponse(['success' => true, 'data' => $data, 'msg' => 'Fetched ' . count($data) . ' logs']);
        break;

    case 'get_attendance_log_tree':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $isAdmin = (strcasecmp($user['system_role'] ?? '', 'Admin') === 0 || strcasecmp($user['system_role'] ?? '', 'HRM') === 0);
        $eid = $user['employee_id'];

        $year  = isset($_POST['year'])  ? (int)$_POST['year']  : 0;
        $month = isset($_POST['month']) ? (int)$_POST['month'] : 0;
        $day   = isset($_POST['day'])   ? (int)$_POST['day']   : 0;

        $where_parts = ['1=1'];
        if (!$isAdmin) {
            $where_parts[] = "l.employee_id = '" . $mysqli->real_escape_string($eid) . "'";
        }

        if ($year > 0 && $month > 0 && $day > 0) {
            // Level 4: Actual records for a specific day
            $date_str = sprintf('%04d-%02d-%02d', $year, $month, $day);
            $where_parts[] = "DATE(l.log_datetime) = '" . $mysqli->real_escape_string($date_str) . "'";
            $where = 'WHERE ' . implode(' AND ', $where_parts);
            $sql = "SELECT l.id, l.employee_id, l.action_type, l.status, l.location_name, l.distance_m, l.late_reason,
                           DATE_FORMAT(l.log_datetime, '%d/%m/%Y %h:%i %p') as log_datetime,
                           u.name as user_name
                    FROM checkin_logs l
                    LEFT JOIN users u ON l.employee_id = u.employee_id
                    $where
                    ORDER BY l.log_datetime ASC";
            $res = $mysqli->query($sql);
            $data = [];
            if ($res) while ($row = $res->fetch_assoc()) $data[] = $row;
            apiResponse(['success' => true, 'type' => 'records', 'data' => $data]);

        } elseif ($year > 0 && $month > 0) {
            // Level 3: Days in a specific month/year
            $where_parts[] = "YEAR(l.log_datetime) = $year";
            $where_parts[] = "MONTH(l.log_datetime) = $month";
            $where = 'WHERE ' . implode(' AND ', $where_parts);
            $sql = "SELECT DAY(l.log_datetime) as `day`, COUNT(*) as `count`
                    FROM checkin_logs l
                    $where
                    GROUP BY DAY(l.log_datetime)
                    ORDER BY `day` DESC";
            $res = $mysqli->query($sql);
            $data = [];
            if ($res) while ($row = $res->fetch_assoc()) $data[] = $row;
            apiResponse(['success' => true, 'type' => 'days', 'data' => $data]);

        } elseif ($year > 0) {
            // Level 2: Months in a specific year
            $where_parts[] = "YEAR(l.log_datetime) = $year";
            $where = 'WHERE ' . implode(' AND ', $where_parts);
            $sql = "SELECT MONTH(l.log_datetime) as `month`, COUNT(*) as `count`
                    FROM checkin_logs l
                    $where
                    GROUP BY MONTH(l.log_datetime)
                    ORDER BY `month` DESC";
            $res = $mysqli->query($sql);
            $data = [];
            if ($res) while ($row = $res->fetch_assoc()) $data[] = $row;
            apiResponse(['success' => true, 'type' => 'months', 'data' => $data]);

        } else {
            // Level 1: All years that have data
            $where = 'WHERE ' . implode(' AND ', $where_parts);
            $sql = "SELECT YEAR(l.log_datetime) as `year`, COUNT(*) as `count`
                    FROM checkin_logs l
                    $where
                    GROUP BY YEAR(l.log_datetime)
                    ORDER BY `year` DESC";
            $res = $mysqli->query($sql);
            $data = [];
            if ($res) while ($row = $res->fetch_assoc()) $data[] = $row;
            apiResponse(['success' => true, 'type' => 'years', 'data' => $data]);
        }
        break;

    case 'get_dept_head':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $hid = (int)($_POST['id'] ?? 0);
        $stmt = $mysqli->prepare("SELECT id, full_name, signature FROM user_custom_heads WHERE id = ? AND creator_id = ? LIMIT 1");
        $stmt->bind_param("ii", $hid, $user['id']);
        $stmt->execute();
        $row = $stmt->get_result()->fetch_assoc();
        apiResponse(['success' => (bool)$row, 'data' => $row]);
        break;
    case 'delete_dept_head':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $hid = (int)($_POST['id'] ?? 0);
        if ($hid <= 0) apiResponse(['success' => false, 'message' => 'Invalid head id']);
        $stmt = $mysqli->prepare("DELETE FROM user_custom_heads WHERE id = ? AND creator_id = ?");
        $stmt->bind_param("ii", $hid, $user['id']);
        $stmt->execute();
        $deleted = $stmt->affected_rows;
        $stmt->close();
        apiResponse([
            'success' => $deleted > 0,
            'message' => $deleted > 0 ? 'Department head deleted' : 'Department head not found'
        ]);
        break;
    case 'save_dept_head':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $hid = (int)($_POST['id'] ?? 0);
        $name = trim($_POST['full_name'] ?? '');
        $sig = $_POST['signature'] ?? null;
        $creator_id = $user['id'];

        if ($hid > 0) {
            $stmt = $mysqli->prepare("UPDATE user_custom_heads SET full_name = ?, signature = ? WHERE id = ? AND creator_id = ?");
            $stmt->bind_param("ssii", $name, $sig, $hid, $creator_id);
        } else {
            $stmt = $mysqli->prepare("INSERT INTO user_custom_heads (full_name, signature, creator_id) VALUES (?, ?, ?)");
            $stmt->bind_param("ssi", $name, $sig, $creator_id);
        }

        if ($stmt->execute()) {
            apiResponse(['success' => true, 'message' => 'រក្សាទុកបានជោគជ័យ', 'id' => ($hid > 0 ? $hid : $mysqli->insert_id)]);
        } else {
            apiResponse(['success' => false, 'message' => 'Failed to save: ' . $mysqli->error]);
        }
        break;

    case 'update_avatar':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $eid = $user['employee_id'];
        $base64Image = $_POST['avatar_base64'] ?? '';
        if (empty($base64Image)) {
            apiResponse(['success' => false, 'message' => 'No image data provided']);
        }

        // Remove data URI scheme prefix if present
        if (strpos($base64Image, 'data:image') === 0) {
            $base64Image = preg_replace('/^data:image\/\w+;base64,/', '', $base64Image);
        }

        $imageData = base64_decode($base64Image);
        if ($imageData === false) {
            apiResponse(['success' => false, 'message' => 'Invalid image data']);
        }

        $fileName = 'avatar_' . $eid . '_' . time() . '.png';
        $uploadPath = __DIR__ . '/uploads/avatars/' . $fileName;

        if (!is_dir(__DIR__ . '/uploads/avatars')) {
            mkdir(__DIR__ . '/uploads/avatars', 0755, true);
        }

        if (file_put_contents($uploadPath, $imageData)) {
            // Save relative URL path to DB
            $avatarUrl = 'uploads/avatars/' . $fileName;
            $stmt = $mysqli->prepare("UPDATE users SET avatar = ? WHERE employee_id = ?");
            if ($stmt) {
                $stmt->bind_param("ss", $avatarUrl, $eid);
                $stmt->execute();
                $stmt->close();

                apiResponse(['success' => true, 'message' => 'Avatar updated successfully', 'avatar' => $avatarUrl]);
            } else {
                 apiResponse(['success' => false, 'message' => 'Database error']);
            }
        } else {
            apiResponse(['success' => false, 'message' => 'Failed to save image']);
        }
        break;

    case 'check_update':
        $current_version = $_POST['version'] ?? '1.0.0';
        $current_build = (int)($_POST['build_number'] ?? 1);

        // Resolve update settings from the authenticated user's owner config first,
        // then fall back to SYSTEM_WIDE inside get_scan_setting().
        $settings_owner_eid = $user['employee_id'] ?? null;
        $latest_version = get_scan_setting('app_latest_version', '1.0.0', $mysqli, $settings_owner_eid);
        $latest_build = (int)get_scan_setting('app_latest_build', '1', $mysqli, $settings_owner_eid);
        $apk_url = get_scan_setting('app_apk_url', 'https://app.vvc.asia/flutter/app-arm64-v8a-release.apk', $mysqli, $settings_owner_eid);
        $update_message = get_scan_setting('app_update_message', 'មានជំនាន់ថ្មី (New Version) សម្រាប់កម្មវិធីនេះ។ សូមធ្វើការអាប់ដេតដើម្បីទទួលបានមុខងារថ្មីៗ។', $mysqli, $settings_owner_eid);
        $force_update = get_scan_setting('app_force_update', '0', $mysqli, $settings_owner_eid) === '1';

        $has_update = ($latest_build > $current_build)
            || version_compare((string)$latest_version, (string)$current_version, '>');

        apiResponse([
            'success' => true,
            'has_update' => $has_update,
            'latest_version' => $latest_version,
            'latest_build' => $latest_build,
            'apk_url' => $apk_url,
            'message' => $update_message,
            'force_update' => $force_update
        ]);
        break;

    case 'get_app_config':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $eid = $user['employee_id'];

        // Resolve admin_id hierarchy
        $owner_id = 'SYSTEM_WIDE';
        $stmt_admin = $mysqli->prepare("SELECT user_role, COALESCE(created_by_admin_id, '') AS created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1");
        if ($stmt_admin) {
            $stmt_admin->bind_param("s", $eid);
            $stmt_admin->execute();
            $res_admin = $stmt_admin->get_result();
            if ($row_admin = $res_admin->fetch_assoc()) {
                $role = $row_admin['user_role'] ?? '';
                $creator = $row_admin['created_by_admin_id'] ?? '';

                // Fallback logic: check if user has their own settings, if not use creator
                $check = $mysqli->prepare("SELECT 1 FROM app_scan_settings WHERE admin_id = ? LIMIT 1");
                $check->bind_param("s", $eid);
                $check->execute();
                if ($check->get_result()->num_rows > 0) {
                    $owner_id = $eid;
                } elseif (!empty($creator)) {
                    $owner_id = $creator;
                } elseif (strcasecmp($role, 'Admin') === 0) {
                    $owner_id = $eid;
                }
                $check->close();
            }
            $stmt_admin->close();
        }

        $settings = [];
        // Pull in order: SYSTEM_WIDE -> Owner. Last one wins in assignment loop.
        $sql = "(SELECT setting_key, setting_value, 0 as priority FROM app_scan_settings WHERE admin_id = 'SYSTEM_WIDE')
                UNION
                (SELECT setting_key, setting_value, 1 as priority FROM app_scan_settings WHERE admin_id = ?)
                ORDER BY priority ASC";

        $stmt = $mysqli->prepare($sql);
        if ($stmt) {
            $stmt->bind_param("s", $owner_id);
            $stmt->execute();
            $result = $stmt->get_result();
            while ($row = $result->fetch_assoc()) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
            $stmt->close();
        }

        apiResponse([
            'success' => true,
            'settings' => $settings,
            'admin_id' => $owner_id
        ]);
        break;

    case 'create_ai_chat_session':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $title = trim((string)($_POST['title'] ?? ''));
        $result = ai_chat_create_session($mysqli, (string)($user['employee_id'] ?? ''), $title);
        apiResponse($result);
        break;

    case 'get_ai_chat_sessions':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $limit = (int)($_POST['limit'] ?? 20);
        $sessions = ai_chat_get_sessions($mysqli, (string)($user['employee_id'] ?? ''), $limit);
        apiResponse([
            'success' => true,
            'sessions' => $sessions,
        ]);
        break;

    case 'get_ai_chat_history':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $sessionId = (int)($_POST['session_id'] ?? 0);
        if ($sessionId <= 0) {
            apiResponse(['success' => false, 'message' => 'Invalid session ID']);
        }
        $session = ai_chat_validate_session_owner($mysqli, $sessionId, (string)($user['employee_id'] ?? ''));
        if (!$session) {
            apiResponse(['success' => false, 'message' => 'Chat session not found']);
        }
        $messages = ai_chat_get_history($mysqli, (string)($user['employee_id'] ?? ''), $sessionId, 100);
        apiResponse([
            'success' => true,
            'session' => $session,
            'messages' => $messages,
        ]);
        break;

    case 'delete_ai_chat_session':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $sessionId = (int)($_POST['session_id'] ?? 0);
        if ($sessionId <= 0) {
            apiResponse(['success' => false, 'message' => 'Invalid session ID']);
        }
        $result = ai_chat_delete_session($mysqli, $sessionId, (string)($user['employee_id'] ?? ''));
        apiResponse($result);
        break;

    case 'delete_all_ai_chat_sessions':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $result = ai_chat_delete_all_sessions($mysqli, (string)($user['employee_id'] ?? ''));
        apiResponse($result);
        break;

    case 'send_ai_chat_message':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $sessionId = (int)($_POST['session_id'] ?? 0);
        $message = trim((string)($_POST['message'] ?? ''));
        if ($message === '') {
            apiResponse(['success' => false, 'message' => 'Message is required']);
        }
        $result = ai_chat_handle_message($mysqli, $user, $sessionId, $message);
        apiResponse($result);
        break;

    // ─── Analyze Product Image (Vision AI) ───────────────────────────────────
    case 'analyze_product_image':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $imageBase64 = trim((string)($_POST['image_base64'] ?? ''));
        $barcodeText  = trim((string)($_POST['barcode'] ?? ''));
        if ($imageBase64 === '' && $barcodeText === '') {
            apiResponse(['success' => false, 'message' => 'image_base64 or barcode is required']);
        }
        // Detect MIME type from base64 header
        $mimeType = 'image/jpeg';
        if (strpos($imageBase64, 'data:') === 0) {
            preg_match('/data:([^;]+);base64,/', $imageBase64, $m);
            $mimeType    = $m[1] ?? 'image/jpeg';
            $imageBase64 = (string)preg_replace('/^data:[^;]+;base64,/', '', $imageBase64);
        }
        $cleanImageBase64 = str_replace(["\r", "\n", " ", "\t"], '', (string)$imageBase64);

        $config = ai_chat_resolve_provider_config();
        if (!$config) {
            apiResponse(['success' => false, 'message' => 'AI provider is not configured']);
        }
        // Build user prompt
        $analysisTarget = $imageBase64 !== ''
            ? 'Analyze this product image carefully.'
            : 'Use the barcode / QR code text to identify the product as accurately as possible.';
        $extraContext = '';
        if ($barcodeText !== '') {
            $extraContext = "\n\nBarcode / QR code detected on the product: **{$barcodeText}**. Please also identify the country of origin based on the barcode prefix (GS1 prefix lookup).";
        }
        $userPrompt = "You are a product analysis expert. {$analysisTarget} Respond in Khmer (ភាសាខ្មែរ) with a structured JSON object. Do not include chain-of-thought, <think> tags, explanations, or markdown. Include all the following fields exactly:\n{\n  \"product_name\": \"...\",\n  \"brand\": \"...\",\n  \"country_of_origin\": \"...\",\n  \"country_flag_emoji\": \"...\",\n  \"category\": \"...\",\n  \"usage\": [\"step1\", \"step2\", ...],\n  \"benefits\": [\"benefit1\", \"benefit2\", ...],\n  \"warnings\": [\"...\"],\n  \"ingredients_summary\": \"...\",\n  \"price_range_usd\": \"...\",\n  \"summary\": \"...\"\n}\nRespond with ONLY the JSON object, no extra text or markdown." . $extraContext;
        $systemPrompt = 'You are a world-class product analyst. Always respond with valid JSON only, using Khmer language for all descriptive values. Never include chain-of-thought, reasoning notes, <think> tags, markdown, or explanatory text outside the JSON object.';
        $visionRes = ai_call_free_vision_service($systemPrompt, $userPrompt, $imageBase64, $mimeType);

        if (!$visionRes['success']) {
            apiResponse(['success' => false, 'message' => 'មិនអាចទាក់ទងប្រព័ន្ធ AI វិភាគរូបភាពបានទេ៖ ' . $visionRes['message']]);
        }

        $rawContent = $visionRes['content'];
        $extracted = product_ai_extract_json_payload($rawContent);

        if (!is_array($extracted) || !is_array($extracted['json'] ?? null)) {
            $fallbackJson = product_ai_fallback_parse_text($rawContent);
            if ($fallbackJson) {
                $extracted = ['json' => $fallbackJson, 'raw' => $rawContent];
            }
        }

        if (!is_array($extracted) || !is_array($extracted['json'] ?? null)) {
            apiResponse([
                'success' => false,
                'message' => 'AI មិនអាចរៀបចំលទ្ធផលបានត្រឹមត្រូវទេ។ សូមព្យាយាមម្តងទៀត។',
                'raw' => $rawContent,
                'parsed' => null,
            ]);
        }
        apiResponse(['success' => true, 'raw' => $extracted['raw'] ?? $rawContent, 'parsed' => $extracted['json']]);
        break;

    case 'remove_ai_chat_image_background':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $employeeId = (string)($user['employee_id'] ?? '');
        $sessionId = (int)($_POST['session_id'] ?? 0);
        $imageBase64 = (string)($_POST['image_base64'] ?? '');
        if (trim($imageBase64) === '') {
            apiResponse(['success' => false, 'message' => 'Image is required']);
        }

        $session = null;
        if ($sessionId > 0) {
            $session = ai_chat_validate_session_owner($mysqli, $sessionId, $employeeId);
            if (!$session) {
                apiResponse(['success' => false, 'message' => 'Chat session not found']);
            }
        } else {
            $created = ai_chat_create_session($mysqli, $employeeId, 'កាត់ Background រូបភាព');
            if (!($created['success'] ?? false)) {
                apiResponse($created);
            }
            $session = $created['session'];
            $sessionId = (int)($session['id'] ?? 0);
        }

        $requestText = 'សូមកាត់ Background រូបភាពនេះជា PNG គ្មានផ្ទៃខាងក្រោយ។';
        ai_chat_insert_message($mysqli, $sessionId, $employeeId, 'user', $requestText, null, null, null, null);

        $imageResult = ai_image_remove_background_to_upload($employeeId, $imageBase64);
        if (!($imageResult['success'] ?? false)) {
            $errorText = 'មិនអាចកាត់ Background រូបភាពនេះបានទេ។ ' . (string)($imageResult['message'] ?? '');
            ai_chat_insert_message($mysqli, $sessionId, $employeeId, 'assistant', $errorText, null, null, null, 'imgly-background-removal');
            apiResponse([
                'success' => false,
                'message' => $errorText,
                'details' => $imageResult['details'] ?? null,
                'session_id' => $sessionId,
                'session_title' => (string)($session['title'] ?? 'AI Assistant'),
            ]);
        }

        $reply = 'រួចហើយ។ ខ្ញុំបានកាត់ Background ហើយបង្កើតជា PNG គ្មានផ្ទៃខាងក្រោយ។';
        $assistantMessageId = ai_chat_insert_message(
            $mysqli,
            $sessionId,
            $employeeId,
            'assistant',
            $reply,
            null,
            null,
            null,
            'imgly-background-removal',
            'image/png',
            (string)($imageResult['image_path'] ?? '')
        );
        ai_chat_touch_session($mysqli, $sessionId, null, 'imgly', 'background-removal-node');

        apiResponse([
            'success' => true,
            'session_id' => $sessionId,
            'session_title' => (string)($session['title'] ?? 'AI Assistant'),
            'message_id' => $assistantMessageId,
            'reply' => $reply,
            'provider' => 'imgly',
            'model' => 'background-removal-node',
            'attachment_type' => 'image/png',
            'attachment_path' => (string)($imageResult['image_path'] ?? ''),
            'image_path' => (string)($imageResult['image_path'] ?? ''),
            'image_base64' => (string)($imageResult['image_base64'] ?? ''),
            'mime_type' => 'image/png',
        ]);
        break;

    case 'regenerate_ai_chat_reply':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $sessionId = (int)($_POST['session_id'] ?? 0);
        if ($sessionId <= 0) {
            apiResponse(['success' => false, 'message' => 'Invalid session ID']);
        }
        $result = ai_chat_regenerate_last_reply($mysqli, $user, $sessionId);
        apiResponse($result);
        break;




    // =============================================
    // FACE REGISTRATION API
    // =============================================

    case 'register_face':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $eid = $user['employee_id'] ?? '';
        if (empty($eid)) apiResponse(['success' => false, 'message' => 'Missing employee ID']);

        $photos_json = $_POST['photos_json'] ?? '';
        $photos = json_decode($photos_json, true);
        if (!is_array($photos) || count($photos) < 1) {
            apiResponse(['success' => false, 'message' => 'ត្រូវការរូបថតយ៉ាងតិច ១ ']);
        }

        // លុបការចុះឈ្មោះចាស់ (re-register)
        $del = $mysqli->prepare("DELETE FROM employee_face_data WHERE employee_id = ?");
        if ($del) { $del->bind_param("s", $eid); $del->execute(); $del->close(); }

        $face_dir = __DIR__ . '/uploads/faces/' . preg_replace('/[^A-Za-z0-9_-]/', '', $eid) . '/';
        if (!is_dir($face_dir)) mkdir($face_dir, 0775, true);

        $saved = 0;
        foreach ($photos as $idx => $b64) {
            $clean_b64 = preg_replace('/^data:image\/[a-z]+;base64,/', '', $b64);
            $img_data = base64_decode($clean_b64, true);
            if (!$img_data) continue;
            $fname = 'face_' . $idx . '_' . time() . '.jpg';
            $fpath = $face_dir . $fname;
            if (file_put_contents($fpath, $img_data)) {
                $rel_path = 'uploads/faces/' . preg_replace('/[^A-Za-z0-9_-]/', '', $eid) . '/' . $fname;
                $stmt = $mysqli->prepare("INSERT INTO employee_face_data (employee_id, photo_path, photo_index) VALUES (?, ?, ?)");
                if ($stmt) {
                    $pi = (int)$idx;
                    $stmt->bind_param("ssi", $eid, $rel_path, $pi);
                    $stmt->execute();
                    $stmt->close();
                    $saved++;
                }
            }
        }

        if ($saved > 0) {
            $mysqli->query("UPDATE users SET face_registered = 1 WHERE employee_id = '" . $mysqli->real_escape_string($eid) . "'");
            apiResponse(['success' => true, 'message' => 'ចុះឈ្មោះ Face ID ជោគជ័យ!', 'photos_saved' => $saved]);
        } else {
            apiResponse(['success' => false, 'message' => 'មិនអាចរក្សាទុករូបថតបានទេ']);
        }
        break;

    case 'get_face_status':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $eid = $user['employee_id'] ?? '';
        $stmt = $mysqli->prepare("SELECT COUNT(*) as cnt, MAX(registered_at) as reg_at FROM employee_face_data WHERE employee_id = ?");
        $registered = false;
        $reg_at = null;
        $photo_count = 0;
        if ($stmt) {
            $stmt->bind_param("s", $eid);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res) {
                $row = $res->fetch_assoc();
                $photo_count = (int)($row['cnt'] ?? 0);
                $registered = $photo_count > 0;
                $reg_at = $row['reg_at'] ?? null;
            }
            $stmt->close();
        }
        // Also get the photo URLs
        $photos = [];
        $stmt2 = $mysqli->prepare("SELECT photo_path, photo_index, registered_at FROM employee_face_data WHERE employee_id = ? ORDER BY photo_index ASC");
        if ($stmt2) {
            $stmt2->bind_param("s", $eid);
            $stmt2->execute();
            $res2 = $stmt2->get_result();
            if ($res2) {
                while ($row2 = $res2->fetch_assoc()) {
                    $base = rtrim(dirname(isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : ''), '/');
                    $host = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . ($_SERVER['HTTP_HOST'] ?? 'localhost');
                    $photos[] = [
                        'path' => $row2['photo_path'],
                        'url' => $host . '/' . ltrim($row2['photo_path'], '/'),
                        'index' => (int)$row2['photo_index'],
                        'registered_at' => $row2['registered_at'],
                    ];
                }
            }
            $stmt2->close();
        }
        apiResponse([
            'success' => true,
            'registered' => $registered,
            'photo_count' => $photo_count,
            'registered_at' => $reg_at,
            'photos' => $photos,
        ]);
        break;

    case 'delete_face':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $caller_eid = $user['employee_id'] ?? '';
        $caller_role = strtolower($user['user_role'] ?? '');
        $target_eid = trim($_POST['target_employee_id'] ?? $caller_eid);

        // Admin/HRM can delete others; Employee can only delete own
        $is_admin = in_array($caller_role, ['admin', 'hrm', 'hr']);
        if ($target_eid !== $caller_eid && !$is_admin) {
            apiResponse(['success' => false, 'message' => 'អ្នកគ្មានសិទ្ធិលុបទិន្នន័យ Face ឈ្នោះទៀត']);
        }

        // Delete photo files
        $res = $mysqli->prepare("SELECT photo_path FROM employee_face_data WHERE employee_id = ?");
        if ($res) {
            $res->bind_param("s", $target_eid);
            $res->execute();
            $r = $res->get_result();
            if ($r) {
                while ($pr = $r->fetch_assoc()) {
                    $fp = __DIR__ . '/' . ltrim($pr['photo_path'], '/');
                    if (is_file($fp)) @unlink($fp);
                }
            }
            $res->close();
        }

        $del2 = $mysqli->prepare("DELETE FROM employee_face_data WHERE employee_id = ?");
        if ($del2) {
            $del2->bind_param("s", $target_eid);
            $del2->execute();
            $del2->close();
        }
        $mysqli->query("UPDATE users SET face_registered = 0 WHERE employee_id = '" . $mysqli->real_escape_string($target_eid) . "'");
        apiResponse(['success' => true, 'message' => 'ទិន្នន័យ Face ត្រូវបានលុបដោយជោគជ័យ']);
        break;

    case 'verify_face':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $eid = $user['employee_id'] ?? '';
        $photo_b64 = $_POST['photo_base64'] ?? '';

        $faceVerification = ai_verify_face_match($mysqli, $eid, $photo_b64);
        $verified = ($faceVerification['match'] ?? false);

        apiResponse([
            'success' => true,
            'verified' => $verified,
            'confidence' => $verified ? 'high' : 'low',
            'message' => $verified ? 'ផ្ទៀងផ្ទាត់ជោគជ័យ' : ($faceVerification['message'] ?? 'ផ្ទៀងផ្ទាត់ Face មិនត្រូវ — សូមព្យាយាមម្ដងទៀត'),
        ]);
        break;

    case 'get_face_registrations':
        // Admin only: list all employees with face registration status
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $caller_role = strtolower($user['user_role'] ?? '');
        if (!in_array($caller_role, ['admin', 'hrm', 'hr'])) {
            apiResponse(['success' => false, 'message' => 'Admin access required']);
        }
        $rows = [];
        $sql_face = "SELECT u.employee_id, u.name, u.department, u.position, u.avatar,
                     COALESCE(u.face_registered, 0) as face_registered,
                     (SELECT COUNT(*) FROM employee_face_data f WHERE f.employee_id = u.employee_id) as photo_count,
                     (SELECT MAX(f2.registered_at) FROM employee_face_data f2 WHERE f2.employee_id = u.employee_id) as registered_at
                     FROM users u
                     WHERE u.status != 'inactive' OR u.status IS NULL
                     ORDER BY u.name ASC";
        $res = $mysqli->query($sql_face);
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $rows[] = [
                    'employee_id' => $row['employee_id'],
                    'name' => $row['name'],
                    'department' => $row['department'],
                    'position' => $row['position'],
                    'avatar' => $row['avatar'],
                    'face_registered' => (bool)$row['face_registered'],
                    'photo_count' => (int)$row['photo_count'],
                    'registered_at' => $row['registered_at'],
                ];
            }
        }
        apiResponse(['success' => true, 'data' => $rows, 'total' => count($rows)]);
        break;

    case 'get_training_questions':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $sql = "SELECT id, question, option_a, option_b, option_c, option_d, correct_option, explanation FROM training_quiz_questions WHERE is_active = 1 ORDER BY id DESC";
        $res = $mysqli->query($sql);
        $questions = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $questions[] = [
                    'id' => (int)$row['id'],
                    'question' => $row['question'],
                    'options' => [
                        $row['option_a'],
                        $row['option_b'],
                        $row['option_c'],
                        $row['option_d']
                    ],
                    'correct_index' => ($row['correct_option'] === 'A' ? 0 : ($row['correct_option'] === 'B' ? 1 : ($row['correct_option'] === 'C' ? 2 : 3))),
                    'explanation' => $row['explanation']
                ];
            }
        }
        apiResponse(['success' => true, 'status' => 'success', 'data' => $questions]);
        break;


    case 'get_material_items':
        $res = $mysqli->query("SELECT id, item_name, quantity, price, category, image_path FROM stock_items ORDER BY item_name ASC");
        $items = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $items[] = [
                    'id' => (int)$row['id'],
                    'item_name' => $row['item_name'],
                    'quantity' => (int)$row['quantity'],
                    'price' => (float)$row['price'],
                    'category' => $row['category'],
                    'image_path' => $row['image_path']
                ];
            }
        }
        apiResponse(['success' => true, 'items' => $items]);
        break;

    case 'submit_material_request':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $location = trim($_POST['location'] ?? 'N/A');
        $title = trim($_POST['title'] ?? ($_POST['remarks'] ?? 'Material Request'));
        if ($title === '') $title = 'Material Request';
        $items_json = $_POST['items'] ?? ($_POST['items_json'] ?? '[]');
        $request_items = json_decode($items_json, true);
        if (!is_array($request_items)) {
            $request_items = [];
        }

        if (empty($request_items)) {
            apiResponse(['success' => false, 'message' => 'No items in request']);
        }

        $mysqli->begin_transaction();
        try {
            // Generate request number
            $request_no = 'REQ-' . date('Ymd') . '-' . rand(1000, 9999);

            $stmt = $mysqli->prepare("INSERT INTO stock_request (user_id, request_no, title, location, status) VALUES (?, ?, ?, ?, 'pending')");
            $user_db_id = (int)$user['id'];
            $stmt->bind_param("isss", $user_db_id, $request_no, $title, $location);
            if (!$stmt->execute()) throw new Exception($stmt->error);

            $request_id = $mysqli->insert_id;
            $stmt->close();

            $stmt_item = $mysqli->prepare("INSERT INTO stock_request_items (stock_request_id, item_id, item_name_custom, requested_quantity, notes) VALUES (?, ?, ?, ?, ?)");

            if ($stmt_item) {
                foreach ($request_items as $item) {
                    $item_id = isset($item['id']) ? (int)$item['id'] : null;
                    $item_name_custom = $item['name'] ?? null;
                    $qty = (int)($item['quantity'] ?? 0);
                    $notes = $item['notes'] ?? '';

                    $stmt_item->bind_param("iisis", $request_id, $item_id, $item_name_custom, $qty, $notes);
                    if (!$stmt_item->execute()) throw new Exception($stmt_item->error);
                }
                $stmt_item->close();
            } else {
                throw new Exception($mysqli->error);
            }

            $mysqli->commit();

            // Optional: Notify via Telegram
            $tg_data = [
                'name' => $user['name'] ?? 'Unknown',
                'request_type' => 'ប័ណ្ណបើកសម្ភារៈ (Material Request)',
                'summary' => "លេខប័ណ្ណ: $request_no\nទីតាំង: $location\nចំនួន: " . count($request_items) . " មុខ",
            ];
            sendRequestTelegram($mysqli, $user['employee_id'], $tg_data);

            apiResponse(['success' => true, 'message' => 'Request submitted successfully', 'request_no' => $request_no]);
        } catch (Exception $e) {
            $mysqli->rollback();
            apiResponse(['success' => false, 'message' => 'Error: ' . $e->getMessage()]);
        }
        break;


    // ===============================================
    // GPS TRIP TRACKING API (Mobile)
    // ===============================================
    case 'get_all_trips':
        // Allow if system_role is Admin/HRM OR if user_role is Admin
        if (!$user || !(strcasecmp($user['system_role'], 'Admin') === 0 || strcasecmp($user['system_role'], 'HRM') === 0 || strcasecmp($user['user_role'], 'Admin') === 0)) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $sql = "SELECT t.*, t.total_distance_km as distance_km,
                COALESCE(u.name, t.employee_name) as user_name,
                u.system_role, u.department
                FROM employee_trips t
                LEFT JOIN users u ON t.employee_id = u.employee_id
                ORDER BY t.started_at DESC LIMIT 500";
        $res = $mysqli->query($sql);
        if (!$res) {
            apiResponse(['success' => false, 'message' => 'Query error: ' . $mysqli->error]);
        }
        $data = [];
        while ($row = $res->fetch_assoc()) {
            $data[] = $row;
        }
        apiResponse(['success' => true, 'data' => $data]);
        break;

    case 'get_trip_details':
        if (!$user) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }
        $is_trip_admin = strcasecmp($user['system_role'] ?? '', 'Admin') === 0
            || strcasecmp($user['system_role'] ?? '', 'HRM') === 0
            || strcasecmp($user['user_role'] ?? '', 'Admin') === 0;
        $trip_id = (int)($_POST['trip_id'] ?? 0);
        if ($trip_id <= 0) apiResponse(['success' => false, 'message' => 'Trip ID required']);

        if ($is_trip_admin) {
            $trip_stmt = $mysqli->prepare("SELECT t.*, u.name as user_name, u.avatar FROM employee_trips t LEFT JOIN users u ON t.employee_id = u.employee_id WHERE t.id = ?");
            $trip_stmt->bind_param('i', $trip_id);
        } else {
            $trip_stmt = $mysqli->prepare("SELECT t.*, u.name as user_name, u.avatar FROM employee_trips t LEFT JOIN users u ON t.employee_id = u.employee_id WHERE t.id = ? AND t.employee_id = ?");
            $trip_stmt->bind_param('is', $trip_id, $user['employee_id']);
        }
        $trip_stmt->execute();
        $trip = $trip_stmt->get_result()->fetch_assoc();
        $trip_stmt->close();

        if (!$trip) apiResponse(['success' => false, 'message' => 'Trip not found']);

        // Calculate live duration if trip is still active
        if (($trip['status'] ?? '') === 'active' && !empty($trip['started_at'])) {
            try {
                $start_time = new DateTime($trip['started_at']);
                $now = new DateTime();
                $trip['duration_minutes'] = (int)round(($now->getTimestamp() - $start_time->getTimestamp()) / 60);
            } catch (Exception $e) {
                // Ignore parsing errors
            }
        }

        $pts_stmt = $mysqli->prepare("SELECT latitude, longitude, speed, accuracy, recorded_at FROM trip_locations WHERE trip_id = ? ORDER BY recorded_at ASC");
        $pts_stmt->bind_param('i', $trip_id);
        $pts_stmt->execute();
        $pts_res = $pts_stmt->get_result();
        $points = [];
        while ($pt = $pts_res->fetch_assoc()) {
            $points[] = $pt;
        }
        $pts_stmt->close();

        $snapped = gps_snap_trip_points_to_roads($points);

        apiResponse([
            'success' => true,
            'trip' => $trip,
            'points' => $points,
            'snapped_points' => $snapped['points'] ?? [],
            'route_source' => $snapped['source'] ?? 'raw',
            'route_message' => $snapped['message'] ?? null,
        ]);
        break;

    case 'get_tracking_customers':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $customers = [];
        $res = $mysqli->query("SELECT * FROM tracking_customers ORDER BY name ASC");
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $customers[] = $row;
            }
        }
        apiResponse(['success' => true, 'data' => $customers]);
        break;

    case 'start_trip':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $eid = $user['employee_id'];
        $empName = $user['name'] ?? '';
        $customer_id = (int)($_POST['customer_id'] ?? 0);
        $customer_name = trim($_POST['customer_name'] ?? '');
        $start_lat = (float)($_POST['latitude'] ?? 0);
        $start_lng = (float)($_POST['longitude'] ?? 0);

        // Check if there's already an active trip for this employee
        $check_stmt = $mysqli->prepare("SELECT id FROM employee_trips WHERE employee_id = ? AND status = 'active' LIMIT 1");
        $check_stmt->bind_param('s', $eid);
        $check_stmt->execute();
        $existing = $check_stmt->get_result()->fetch_assoc();
        $check_stmt->close();

        if ($existing) {
            apiResponse(['success' => false, 'message' => 'អ្នកមានដំណើរមួយដែលកំពុងដំណើរការរួចហើយ។ សូមបញ្ចប់វាមុន។', 'active_trip_id' => $existing['id']]);
        }

        $stmt = $mysqli->prepare("INSERT INTO employee_trips (employee_id, employee_name, customer_id, customer_name, start_lat, start_lng, status, started_at) VALUES (?, ?, ?, ?, ?, ?, 'active', NOW())");
        $stmt->bind_param('ssisdd', $eid, $empName, $customer_id, $customer_name, $start_lat, $start_lng);

        if ($stmt->execute()) {
            $trip_id = $mysqli->insert_id;

            // Record the starting location
            $loc_stmt = $mysqli->prepare("INSERT INTO trip_locations (trip_id, latitude, longitude, speed, accuracy, recorded_at) VALUES (?, ?, ?, 0, 0, NOW())");
            $loc_stmt->bind_param('idd', $trip_id, $start_lat, $start_lng);
            $loc_stmt->execute();
            $loc_stmt->close();

            // ===== Telegram Group Notification to HR & Admin =====
            $bot_token = getTelegramBotToken($mysqli, $eid);
            $tg_chat_id = '';
            $tg_res = $mysqli->query("SELECT setting_value FROM system_settings WHERE setting_key = 'telegram_chat_id' LIMIT 1");
            if ($tg_res && $tg_row = $tg_res->fetch_assoc()) $tg_chat_id = $tg_row['setting_value'];
            if (empty($tg_chat_id)) $tg_chat_id = defined('TELEGRAM_CHAT_ID') ? TELEGRAM_CHAT_ID : '';

            if (!empty($bot_token) && !empty($tg_chat_id)) {
                $now_str = date('d-m-Y H:i');
                $tg_msg  = "🚗 <b>ការចាប់ផ្ដើមដំណើរថ្មី!</b>\n\n";
                $tg_msg .= "👤 <b>បុគ្គលិក:</b> " . htmlspecialchars($empName) . " (" . htmlspecialchars($eid) . ")\n";
                $tg_msg .= "📍 <b>គោលដៅ:</b> " . htmlspecialchars($customer_name) . "\n";
                $tg_msg .= "⏰ <b>ចាប់ផ្ដើម:</b> " . $now_str . "\n";
                $tg_msg .= "🆔 <b>Trip ID:</b> #" . $trip_id;

                $tg_url = "https://api.telegram.org/bot{$bot_token}/sendMessage";
                $tg_payload = ['chat_id' => $tg_chat_id, 'text' => $tg_msg, 'parse_mode' => 'HTML'];
                $ch = curl_init();
                curl_setopt($ch, CURLOPT_URL, $tg_url);
                curl_setopt($ch, CURLOPT_POST, true);
                curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($tg_payload));
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_TIMEOUT, 5);
                @curl_exec($ch);
                curl_close($ch);
            }
            // ====================================================

            // Notify HRM/Admin — In-app DB + FCM Push Notification to Flutter app
            $trip_extra = [
                'type'          => 'new_trip',
                'trip_id'       => (string)$trip_id,
                'employee_id'   => $eid,
                'employee_name' => $empName,
                'customer_name' => $customer_name,
                'navigate_to'   => 'gps_tracking',
            ];
            sendAppNotificationToRoles(
                $mysqli,
                ['HRM', 'Admin'],
                '🚗 ការចាប់ផ្ដើមដំណើរថ្មី',
                "បុគ្គលិក {$empName} ({$eid}) បានចាប់ផ្ដើមដំណើរ #{$trip_id} ទៅ {$customer_name}",
                'SYSTEM',
                null,
                null,
                $trip_extra
            );

            apiResponse(['success' => true, 'message' => 'ដំណើរត្រូវបានចាប់ផ្ដើម!', 'trip_id' => $trip_id]);
        } else {
            apiResponse(['success' => false, 'message' => 'កំហុសក្នុងការបង្កើតដំណើរ: ' . $stmt->error]);
        }
        $stmt->close();
        break;

    case 'update_trip_location':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $trip_id = (int)($_POST['trip_id'] ?? 0);
        $lat = (float)($_POST['latitude'] ?? 0);
        $lng = (float)($_POST['longitude'] ?? 0);
        $speed = (float)($_POST['speed'] ?? 0);
        $accuracy = (float)($_POST['accuracy'] ?? 0);

        if ($trip_id <= 0) {
            apiResponse(['success' => false, 'message' => 'Trip ID required']);
        }

        // Verify trip belongs to this user and is active
        $verify = $mysqli->prepare("SELECT id FROM employee_trips WHERE id = ? AND employee_id = ? AND status = 'active'");
        $verify->bind_param('is', $trip_id, $user['employee_id']);
        $verify->execute();
        $trip_exists = $verify->get_result()->fetch_assoc();
        $verify->close();

        if (!$trip_exists) {
            apiResponse(['success' => false, 'message' => 'Trip not found or already completed']);
        }

        $stmt = $mysqli->prepare("INSERT INTO trip_locations (trip_id, latitude, longitude, speed, accuracy, recorded_at) VALUES (?, ?, ?, ?, ?, NOW())");
        $stmt->bind_param('idddd', $trip_id, $lat, $lng, $speed, $accuracy);

        if ($stmt->execute()) {
            // Always update duration in real-time
            $mysqli->query("UPDATE employee_trips SET
                            duration_minutes = TIMESTAMPDIFF(MINUTE, started_at, NOW())
                            WHERE id = $trip_id");

            // Increment total distance in real-time if we have a previous point
            $dist_res = $mysqli->query("SELECT latitude, longitude FROM trip_locations WHERE trip_id = $trip_id ORDER BY id DESC LIMIT 2");
            if ($dist_res && $dist_res->num_rows == 2) {
                $p1 = $dist_res->fetch_assoc(); // New point
                $p2 = $dist_res->fetch_assoc(); // Previous point

                $inc_dist_km = haversine_distance($p1['latitude'], $p1['longitude'], $p2['latitude'], $p2['longitude']) / 1000;

                $mysqli->query("UPDATE employee_trips SET
                                total_distance_km = total_distance_km + $inc_dist_km
                                WHERE id = $trip_id");
            }
            apiResponse(['success' => true, 'message' => 'Location recorded']);
        } else {
            apiResponse(['success' => false, 'message' => 'Failed to record location']);
        }
        $stmt->close();
        break;

    case 'end_trip':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $trip_id = (int)($_POST['trip_id'] ?? 0);
        $eid = $user['employee_id'];

        if ($trip_id <= 0) {
            apiResponse(['success' => false, 'message' => 'Trip ID required']);
        }

        // Get trip
        $trip_stmt = $mysqli->prepare("SELECT * FROM employee_trips WHERE id = ? AND employee_id = ? AND status = 'active'");
        $trip_stmt->bind_param('is', $trip_id, $eid);
        $trip_stmt->execute();
        $trip = $trip_stmt->get_result()->fetch_assoc();
        $trip_stmt->close();

        if (!$trip) {
            apiResponse(['success' => false, 'message' => 'Trip not found or already completed']);
        }

        // Get last location
        $loc_stmt = $mysqli->prepare("SELECT latitude, longitude FROM trip_locations WHERE trip_id = ? ORDER BY recorded_at DESC LIMIT 1");
        $loc_stmt->bind_param('i', $trip_id);
        $loc_stmt->execute();
        $last_loc = $loc_stmt->get_result()->fetch_assoc();
        $loc_stmt->close();

        $end_lat = $last_loc['latitude'] ?? 0;
        $end_lng = $last_loc['longitude'] ?? 0;

        // Calculate total distance
        $pts_stmt = $mysqli->prepare("SELECT latitude, longitude FROM trip_locations WHERE trip_id = ? ORDER BY recorded_at ASC");
        $pts_stmt->bind_param('i', $trip_id);
        $pts_stmt->execute();
        $pts_res = $pts_stmt->get_result();
        $total_dist = 0;
        $prev = null;
        while ($pt = $pts_res->fetch_assoc()) {
            if ($prev) {
                $d = haversine_distance($prev['latitude'], $prev['longitude'], $pt['latitude'], $pt['longitude']);
                $total_dist += $d / 1000; // Convert meters to km (haversine_distance in api.php returns meters)
            }
            $prev = $pt;
        }
        $pts_stmt->close();

        // Update trip
        $update_stmt = $mysqli->prepare("UPDATE employee_trips SET status='completed', end_lat=?, end_lng=?, total_distance_km=?, duration_minutes=TIMESTAMPDIFF(MINUTE, started_at, NOW()), ended_at=NOW() WHERE id=?");
        $update_stmt->bind_param('dddi', $end_lat, $end_lng, $total_dist, $trip_id);
        $update_stmt->execute();

        // Fetch the calculated duration for response
        $dur_stmt = $mysqli->prepare("SELECT duration_minutes FROM employee_trips WHERE id=?");
        $dur_stmt->bind_param('i', $trip_id);
        $dur_stmt->execute();
        $dur_res = $dur_stmt->get_result()->fetch_assoc();
        $duration = (int)($dur_res['duration_minutes'] ?? 0);
        $dur_stmt->close();

        $update_stmt->close();

        apiResponse([
            'success' => true,
            'message' => 'ដំណើរត្រូវបានបញ្ចប់!',
            'trip' => [
                'id' => $trip_id,
                'total_distance_km' => round($total_dist, 3),
                'duration_minutes' => $duration
            ]
        ]);
        break;

    case 'update_customer_location':
        // Auto-save customer lat/lng when trip ends (only if not already set)
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $customer_id = (int)($_POST['customer_id'] ?? 0);
        $lat = (float)($_POST['latitude'] ?? 0);
        $lng = (float)($_POST['longitude'] ?? 0);
        if ($customer_id <= 0 || $lat == 0 || $lng == 0) {
            apiResponse(['success' => false, 'message' => 'Invalid parameters']);
        }
        // Only update if latitude/longitude are NULL or 0
        $chk = $mysqli->prepare("SELECT id, latitude, longitude FROM tracking_customers WHERE id = ?");
        $chk->bind_param('i', $customer_id);
        $chk->execute();
        $cust = $chk->get_result()->fetch_assoc();
        $chk->close();
        if (!$cust) apiResponse(['success' => false, 'message' => 'Customer not found']);
        if (!empty($cust['latitude']) && $cust['latitude'] != 0) {
            // Already has location — skip
            apiResponse(['success' => true, 'updated' => false, 'message' => 'Customer already has location']);
        }
        $upd = $mysqli->prepare("UPDATE tracking_customers SET latitude=?, longitude=? WHERE id=?");
        $upd->bind_param('ddi', $lat, $lng, $customer_id);
        if ($upd->execute()) {
            apiResponse(['success' => true, 'updated' => true, 'message' => 'ទីតាំងអតិថិជនបានរក្សាទុក']);
        } else {
            apiResponse(['success' => false, 'message' => $mysqli->error]);
        }
        $upd->close();
        break;

    case 'get_my_trips':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $eid = $user['employee_id'];
        $trips = [];
        $stmt = $mysqli->prepare("SELECT id, employee_id, customer_id, total_distance_km,
                                  DATE_FORMAT(started_at, '%d/%m/%Y %h:%i %p') as started_at,
                                  DATE_FORMAT(ended_at, '%d/%m/%Y %h:%i %p') as ended_at,
                                  status
                                  FROM employee_trips WHERE employee_id = ? ORDER BY started_at DESC LIMIT 50");
        $stmt->bind_param('s', $eid);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $trips[] = $row;
            }
        } else {
            // Fallback if mysqlnd is missing
            $stmt->store_result();
            if ($stmt->num_rows > 0) {
                $stmt->bind_result($t_id, $t_eid, $t_cid, $t_dist, $t_start, $t_end, $t_status);
                while ($stmt->fetch()) {
                    $trips[] = [
                        'id' => $t_id, 'employee_id' => $t_eid, 'customer_id' => $t_cid,
                        'total_distance_km' => $t_dist, 'started_at' => $t_start,
                        'ended_at' => $t_end, 'status' => $t_status
                    ];
                }
            }
        }
        $stmt->close();
        apiResponse(['success' => true, 'data' => $trips]);
        break;

    case 'get_active_trip':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);

        $eid = $user['employee_id'];
        $stmt = $mysqli->prepare("SELECT t.*, c.latitude as target_lat, c.longitude as target_lng
                                  FROM employee_trips t
                                  LEFT JOIN tracking_customers c ON t.customer_id = c.id
                                  WHERE t.employee_id = ? AND t.status = 'active'
                                  ORDER BY t.started_at DESC LIMIT 1");
        $stmt->bind_param('s', $eid);
        $stmt->execute();
        $trip = $stmt->get_result()->fetch_assoc();
        $stmt->close();

        apiResponse(['success' => true, 'trip' => $trip]);
        break;

    case 'get_payroll_history':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        $eid = $_POST['employee_id'] ?? $user['employee_id'];

        // Ensure only Admin/HRM can view others
        if (strcasecmp($user['system_role'] ?? '', 'Admin') !== 0 && strcasecmp($user['system_role'] ?? '', 'HRM') !== 0) {
            $eid = $user['employee_id'];
        }

        // Ensure table exists
        $mysqli->query("CREATE TABLE IF NOT EXISTS payroll_history (
            id INT AUTO_INCREMENT PRIMARY KEY,
            employee_id VARCHAR(64) NOT NULL,
            payroll_month INT NOT NULL,
            payroll_year INT NOT NULL,
            base_salary DOUBLE DEFAULT 0,
            present_days INT DEFAULT 0,
            calculated_salary DOUBLE DEFAULT 0,
            status VARCHAR(50) DEFAULT 'Pending',
            payment_date DATE DEFAULT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            KEY idx_payroll_emp (employee_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // Get current base salary
        $stmt = $mysqli->prepare("SELECT base_salary FROM users WHERE employee_id = ?");
        $base_salary = 0;
        if ($stmt) {
            $stmt->bind_param("s", $eid);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res && $row = $res->fetch_assoc()) {
                $base_salary = $row['base_salary'] ?? 0;
            }
            $stmt->close();
        }

        // Get payroll history
        $history = [];
        $stmt = $mysqli->prepare("SELECT *, DATE_FORMAT(payment_date, '%d/%m/%Y') as payment_date FROM payroll_history WHERE employee_id = ? ORDER BY payroll_year DESC, payroll_month DESC");
        if ($stmt) {
            $stmt->bind_param("s", $eid);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res) {
                while ($row = $res->fetch_assoc()) {
                    $history[] = $row;
                }
            }
            $stmt->close();
        }

        apiResponse(['success' => true, 'base_salary' => $base_salary, 'data' => $history]);
        break;

    case 'record_payroll_biometric_verification':
        if (!$user) apiResponse(['success' => false, 'message' => 'Unauthorized']);
        ensure_payroll_biometric_records_table($mysqli);

        $eid = (string)($user['employee_id'] ?? '');
        $employee_name = (string)($user['name'] ?? '');
        $purpose = 'payroll';
        $platform = substr(trim((string)($_POST['platform'] ?? 'Unknown')), 0, 80);
        $auth_method = substr(trim((string)($_POST['auth_method'] ?? 'device_biometric_or_passcode')), 0, 80);
        $ip_address = substr((string)($_SERVER['REMOTE_ADDR'] ?? ''), 0, 45);
        $user_agent = substr((string)($_SERVER['HTTP_USER_AGENT'] ?? ''), 0, 255);

        if ($eid === '') {
            apiResponse(['success' => false, 'message' => 'Missing employee id']);
        }

        $sql = "INSERT INTO payroll_biometric_records
                    (employee_id, employee_name, purpose, verification_count, first_verified_at, last_verified_at, last_platform, last_auth_method, last_ip_address, last_user_agent)
                VALUES (?, ?, ?, 1, NOW(), NOW(), ?, ?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    employee_name = VALUES(employee_name),
                    verification_count = verification_count + 1,
                    last_verified_at = NOW(),
                    last_platform = VALUES(last_platform),
                    last_auth_method = VALUES(last_auth_method),
                    last_ip_address = VALUES(last_ip_address),
                    last_user_agent = VALUES(last_user_agent)";
        $stmt = $mysqli->prepare($sql);
        if (!$stmt) {
            apiResponse(['success' => false, 'message' => 'Prepare failed: ' . $mysqli->error]);
        }
        $stmt->bind_param("sssssss", $eid, $employee_name, $purpose, $platform, $auth_method, $ip_address, $user_agent);
        $ok = $stmt->execute();
        $stmt->close();

        apiResponse(['success' => $ok, 'message' => $ok ? 'Recorded' : 'Failed to record biometric verification']);
        break;

    case 'get_all_payroll':
        // Only Admin or HRM can view all payrolls
        if (!$user || !(strcasecmp($user['system_role'], 'Admin') === 0 || strcasecmp($user['system_role'], 'HRM') === 0)) {
            apiResponse(['success' => false, 'message' => 'Unauthorized']);
        }

        $sql = "SELECT employee_id, name, position, department, branch, COALESCE(base_salary, 0) as salary
                FROM users
                WHERE employment_status IS NULL OR employment_status != 'Resigned'
                ORDER BY name ASC";
        $res = $mysqli->query($sql);
        $data = [];
        if ($res) {
            while ($row = $res->fetch_assoc()) {
                $data[] = $row;
            }
            apiResponse(['success' => true, 'data' => $data]);
        } else {
            apiResponse(['success' => false, 'message' => 'SQL Error: ' . $mysqli->error]);
        }
        break;

    default:
        $len = strlen($action);
        $hex = bin2hex($action);
        apiResponse(['success' => false, 'message' => "Action '$action' (len:$len, hex:$hex) not implemented in Central API"]);
        break;
}

function ai_call_free_vision_service($systemPrompt, $userPrompt, $imageBase64 = '', $mimeType = 'image/jpeg') {
    $cleanImageBase64 = str_replace(["\r", "\n", " ", "\t"], '', (string)$imageBase64);

        $userContent = [];
        if ($userPrompt !== '') {
            $userContent[] = ['type' => 'text', 'text' => $userPrompt];
        }
        if ($cleanImageBase64 !== '') {
            $userContent[] = [
                'type' => 'image_url',
                'image_url' => ['url' => "data:{$mimeType};base64,{$cleanImageBase64}"]
            ];
        }

        $messages = [
            ['role' => 'system', 'content' => $systemPrompt],
            ['role' => 'user', 'content' => $userContent],
        ];

        $openAiKey = trim((string)(defined('OPENAI_API_KEY') ? OPENAI_API_KEY : (getenv('OPENAI_API_KEY') ?: '')));
        $groqKey   = trim((string)(defined('GROQ_API_KEY') ? GROQ_API_KEY : (getenv('GROQ_API_KEY') ?: '')));
        $geminiKey = trim((string)(defined('GEMINI_API_KEY') ? GEMINI_API_KEY : (getenv('GEMINI_API_KEY') ?: '')));

        $candidates = [];

        // 1. Google Gemini API (100% Free Tier if key available)
        if ($geminiKey !== '') {
            $candidates[] = [
                'type'     => 'gemini',
                'endpoint' => 'https://generativelanguage.googleapis.com/v1/models/gemini-2.0-flash:generateContent?key=' . $geminiKey,
                'model'    => 'gemini-2.0-flash',
            ];
            $candidates[] = [
                'type'     => 'gemini',
                'endpoint' => 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' . $geminiKey,
                'model'    => 'gemini-2.0-flash',
            ];
            $candidates[] = [
                'type'     => 'gemini',
                'endpoint' => 'https://generativelanguage.googleapis.com/v1/models/gemini-1.5-flash:generateContent?key=' . $geminiKey,
                'model'    => 'gemini-1.5-flash',
            ];
            $candidates[] = [
                'type'     => 'gemini',
                'endpoint' => 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . $geminiKey,
                'model'    => 'gemini-1.5-flash',
            ];
        } else {
            // 2. Groq Cloud Vision (If active)
            if ($groqKey !== '') {
                $candidates[] = [
                    'type'     => 'openai_compat',
                    'endpoint' => 'https://api.groq.com/openai/v1/chat/completions',
                    'key'      => $groqKey,
                    'model'    => 'qwen/qwen3.6-27b',
                ];
            }

            // 3. OpenAI API (Fallback if active)
            if ($openAiKey !== '') {
                $candidates[] = [
                    'type'     => 'openai_compat',
                    'endpoint' => 'https://api.openai.com/v1/chat/completions',
                    'key'      => $openAiKey,
                    'model'    => 'gpt-4o-mini',
                ];
            }

            // 4. Pollinations AI (100% Free Public Vision Engine - Fallback)
            $candidates[] = [
                'type'     => 'pollinations',
                'endpoint' => 'https://text.pollinations.ai/',
                'model'    => 'openai',
            ];
        }

        $lastError = 'Unknown error';

        foreach ($candidates as $cand) {
            if ($cand['type'] === 'pollinations') {
                $payload = [
                    'messages' => $messages,
                    'model'    => $cand['model'],
                    'jsonMode' => true,
                ];
                $attempt = ai_chat_http_post_json($cand['endpoint'], $payload, ['Content-Type: application/json']);
                if ($attempt['ok'] ?? false) {
                    $rawText = '';
                    if (is_string($attempt['data'] ?? null)) {
                        $rawText = trim($attempt['data']);
                    } elseif (!empty($attempt['data']['choices'][0]['message']['content'])) {
                        $rawText = trim((string)$attempt['data']['choices'][0]['message']['content']);
                    }
                    if ($rawText !== '') {
                        return ['success' => true, 'content' => $rawText];
                    }
                }
                $lastError = $attempt['message'] ?? 'Pollinations vision failed';
            } elseif ($cand['type'] === 'gemini') {
                $parts = [['text' => $systemPrompt . "\n\n" . $userPrompt]];
                if ($cleanImageBase64 !== '') {
                    $parts[] = [
                        'inline_data' => [
                            'mime_type' => $mimeType,
                            'data'      => $cleanImageBase64,
                        ]
                    ];
                }
                $payload = [
                    'contents' => [['parts' => $parts]],
                    'generationConfig' => [
                        'temperature' => 0.1,
                        'maxOutputTokens' => 1500,
                        'responseMimeType' => 'application/json'
                    ]
                ];
                $attempt = ai_chat_http_post_json($cand['endpoint'], $payload, ['Content-Type: application/json']);
                if (($attempt['ok'] ?? false) && !empty($attempt['data']['candidates'][0]['content']['parts'][0]['text'])) {
                    $rawText = trim((string)$attempt['data']['candidates'][0]['content']['parts'][0]['text']);
                    return ['success' => true, 'content' => $rawText];
                }
                $lastError = $attempt['data']['error']['message'] ?? ($attempt['message'] ?? 'Gemini vision failed');
            } elseif ($cand['type'] === 'openai_compat') {
                $payload = [
                    'model'       => $cand['model'],
                    'messages'    => $messages,
                    'temperature' => 0.1,
                    'max_tokens'  => 2500,
                ];
                if (strpos($cand['endpoint'], 'openai.com') !== false) {
                    $payload['response_format'] = ['type' => 'json_object'];
                }
                if (strpos($cand['endpoint'], 'groq.com') !== false) {
                    $payload['reasoning_format'] = 'hidden';
                }
                $attempt = ai_chat_http_post_json($cand['endpoint'], $payload, ['Authorization: Bearer ' . $cand['key']]);
                if (($attempt['ok'] ?? false) && !empty($attempt['data']['choices'][0]['message']['content'])) {
                    $rawText = trim((string)$attempt['data']['choices'][0]['message']['content']);
                    return ['success' => true, 'content' => $rawText];
                }
                $lastError = $attempt['data']['error']['message'] ?? ($attempt['message'] ?? 'OpenAI vision failed');
            }
        }

        return ['success' => false, 'message' => $lastError];
}

function ai_verify_face_match($mysqli, $eid, $photo_b64) {
    if (empty($photo_b64)) {
        return ['match' => false, 'message' => 'ត្រូវការរូបថតដើម្បីផ្ទៀងផ្ទាត់ផ្ទៃមុខ'];
    }

    // Check if user has registered face photos
    $count_stmt = $mysqli->prepare("SELECT COUNT(*) as cnt FROM employee_face_data WHERE employee_id = ?");
    $face_count = 0;
    if ($count_stmt) {
        $count_stmt->bind_param("s", $eid);
        $count_stmt->execute();
        $r = $count_stmt->get_result();
        if ($r) { $row = $r->fetch_assoc(); $face_count = (int)($row['cnt'] ?? 0); }
        $count_stmt->close();
    }

    if ($face_count === 0) {
        return ['match' => false, 'message' => 'អ្នកមិនទាន់បានចុះឈ្មោះ Face ID ទេ។ សូមចុះឈ្មោះ Face ID នៅក្នុង Profile ជាមុនសិន!'];
    }

    // Get all registered reference photos (max 1 to save tokens and prevent Groq TPM limit errors)
    $ref_stmt = $mysqli->prepare("SELECT photo_path, photo_index FROM employee_face_data WHERE employee_id = ? ORDER BY photo_index ASC LIMIT 1");
    $ref_photos = [];
    if ($ref_stmt) {
        $ref_stmt->bind_param("s", $eid);
        $ref_stmt->execute();
        $r = $ref_stmt->get_result();
        if ($r) {
            while ($row = $r->fetch_assoc()) {
                $path = $row['photo_path'] ?? '';
                $fullPath = __DIR__ . '/' . ltrim($path, '/');
                if ($path !== '' && is_file($fullPath)) {
                    $bytes = file_get_contents($fullPath);
                    if ($bytes) {
                        $ref_photos[(int)$row['photo_index']] = base64_encode($bytes);
                    }
                }
            }
        }
        $ref_stmt->close();
    }

    if (empty($ref_photos)) {
        return ['match' => false, 'message' => 'អ្នកមិនទាន់បានចុះឈ្មោះ Face ID ទេ។ សូមចុះឈ្មោះ Face ID នៅក្នុង Profile ជាមុនសិន!'];
    }

    $clean_scan_b64 = preg_replace('/^data:image\/[a-z]+;base64,/', '', $photo_b64);
    $cleanScanB64 = str_replace(["\r", "\n", " ", "\t"], '', (string)$photo_b64);

    $config = ai_chat_resolve_provider_config();
    if (!$config) {
        // Security: If AI is not configured, deny face scan — user must use QR code instead
        return ['match' => false, 'message' => 'ម៉ាស៊ីន AI សម្រាប់ផ្ទៀងផ្ទាត់ផ្ទៃមុខមិនទាន់ត្រូវបានកំណត់ទេ។ សូមទាក់ទងអ្នកគ្រប់គ្រង!'];
    }

    $openAiKey = trim((string)(defined('OPENAI_API_KEY') ? OPENAI_API_KEY : (getenv('OPENAI_API_KEY') ?: '')));
    $groqKey   = trim((string)(defined('GROQ_API_KEY') ? GROQ_API_KEY : (getenv('GROQ_API_KEY') ?: '')));
    $geminiKey = trim((string)(defined('GEMINI_API_KEY') ? GEMINI_API_KEY : (getenv('GEMINI_API_KEY') ?: '')));

    $candidates = [];
    if ($geminiKey !== '') {
        $candidates[] = ['provider' => 'gemini', 'model' => 'gemini-2.0-flash', 'endpoint' => 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=' . $geminiKey, 'key' => $geminiKey];
    }
    if ($groqKey !== '') {
        $candidates[] = ['provider' => 'groq', 'model' => 'qwen/qwen3.6-27b', 'endpoint' => 'https://api.groq.com/openai/v1/chat/completions', 'key' => $groqKey];
    }
    if ($openAiKey !== '') {
        $candidates[] = ['provider' => 'openai', 'model' => 'gpt-4o-mini', 'endpoint' => 'https://api.openai.com/v1/chat/completions', 'key' => $openAiKey];
    }

    $promptText = "You are a high-precision, strict biometric facial recognition system.\n";
    $promptText .= "Compare the scanned check-in face (last image) against the registered reference faces of the employee:\n";
    $imgCount = 1;
    foreach ($ref_photos as $index => $b64) {
        $angle = ($index == 0) ? "Straight view" : (($index == 1) ? "Left-tilted view" : "Right-tilted view");
        $promptText .= "- Image $imgCount: $angle of the registered employee.\n";
        $imgCount++;
    }
    $promptText .= "- Image $imgCount: Scanned face during attendance check-in.\n\n";
    $promptText .= "Perform a strict biometric 3D facial feature verification:\n";
    $promptText .= "1. Compare spacing/shape of eyes, nose bridge profile, nose tip structure, mouth shape, jawline structure, cheekbones, and ear positions.\n";
    $promptText .= "2. Disregard background, lighting, minor expressions, or slight angle differences.\n";
    $promptText .= "3. Be highly critical of twins, family members, or similar-looking individuals. If facial bone structure or details do not match the references, they are NOT the same person.\n";
    $promptText .= "4. Only return match: true if you are 98% or more certain that the scanned face (last image) is the exact same human person as the reference photos. Otherwise, return match: false.\n\n";
    $promptText .= "Respond strictly in JSON: {\"match\": true} or {\"match\": false}.";

    $lastError = 'No candidate vision APIs responded.';

    foreach ($candidates as $cand) {
        $rawContent = null;
        if ($cand['provider'] === 'gemini') {
            $parts = [['text' => $promptText]];
            foreach ($ref_photos as $b64) {
                $parts[] = ['inline_data' => ['mime_type' => 'image/jpeg', 'data' => str_replace(["\r", "\n", " ", "\t"], '', $b64)]];
            }
            $parts[] = ['inline_data' => ['mime_type' => 'image/jpeg', 'data' => $cleanScanB64]];

            $payload = ['contents' => [['parts' => $parts]], 'generationConfig' => ['temperature' => 0.0, 'responseMimeType' => 'application/json']];
            $attempt = ai_chat_http_post_json($cand['endpoint'], $payload, ['Content-Type: application/json']);
            if (($attempt['ok'] ?? false) && !empty($attempt['data']['candidates'][0]['content']['parts'][0]['text'])) {
                $rawContent = trim((string)$attempt['data']['candidates'][0]['content']['parts'][0]['text']);
            } else {
                $lastError = $attempt['data']['error']['message'] ?? ($attempt['message'] ?? 'Gemini call failed');
                @file_put_contents(__DIR__ . '/uploads/face_match_debug.log', date('[Y-m-d H:i:s] ') . "API call failed for Gemini | Error: " . $lastError . "\n", FILE_APPEND);
            }
        } else {
            $userContent = [['type' => 'text', 'text' => $promptText]];
            foreach ($ref_photos as $b64) {
                $userContent[] = ['type' => 'image_url', 'image_url' => ['url' => 'data:image/jpeg;base64,' . str_replace(["\r", "\n", " ", "\t"], '', $b64)]];
            }
            $userContent[] = ['type' => 'image_url', 'image_url' => ['url' => 'data:image/jpeg;base64,' . $cleanScanB64]];

            $messages = [
                [
                    'role' => 'user',
                    'content' => $userContent,
                ],
            ];
            $payload = ['model' => $cand['model'], 'messages' => $messages, 'max_tokens' => 800, 'temperature' => 0.0];
            if ($cand['provider'] === 'openai') $payload['response_format'] = ['type' => 'json_object'];
            if ($cand['provider'] === 'groq') {
                $payload['reasoning_format'] = 'hidden';
            }
            $attempt = ai_chat_http_post_json($cand['endpoint'], $payload, ['Authorization: Bearer ' . $cand['key']]);
            if (($attempt['ok'] ?? false) && !empty($attempt['data']['choices'][0]['message']['content'])) {
                $rawContent = trim((string)$attempt['data']['choices'][0]['message']['content']);
            } else {
                $lastError = $attempt['data']['error']['message'] ?? ($attempt['message'] ?? 'Groq/OpenAI call failed');
                @file_put_contents(__DIR__ . '/uploads/face_match_debug.log', date('[Y-m-d H:i:s] ') . "API call failed for Groq/OpenAI | Error: " . $lastError . " | Full Response: " . json_encode($attempt, JSON_UNESCAPED_UNICODE) . "\n", FILE_APPEND);
            }
        }

        if (!empty($rawContent)) {
            // Write debug log to help trace false matches
            @file_put_contents(__DIR__ . '/uploads/face_match_debug.log', date('[Y-m-d H:i:s] ') . "Provider: " . $cand['provider'] . " | Model: " . $cand['model'] . " | Response: " . str_replace(["\r", "\n"], " ", $rawContent) . "\n", FILE_APPEND);

            $extracted = product_ai_extract_json_payload($rawContent);
            if (is_array($extracted) && is_array($extracted['json'] ?? null)) {
                $isMatch = ($extracted['json']['match'] == true || (isset($extracted['json']['is_same_person']) && $extracted['json']['is_same_person'] == true));
                return ['match' => $isMatch, 'message' => $isMatch ? 'Verified' : 'ការផ្ទៀងផ្ទាត់ផ្ទៃមុខមិនត្រូវគ្នាទេ! មុខដែលបានស្កេន មិនមែនជា Face ID របស់គណនីនេះឡើយ。'];
            }
            
            // Secure fallback: only check for explicit key-value match pairs
            $cleanRaw = strtolower($rawContent);
            if (preg_match('/"match"\s*:\s*true/i', $cleanRaw) || preg_match('/"is_same_person"\s*:\s*true/i', $cleanRaw)) {
                return ['match' => true, 'message' => 'Verified'];
            }
            if (preg_match('/"match"\s*:\s*false/i', $cleanRaw) || preg_match('/"is_same_person"\s*:\s*false/i', $cleanRaw)) {
                return ['match' => false, 'message' => 'ការផ្ទៀងផ្ទាត់ផ្ទៃមុខមិនត្រូវគ្នាទេ! មុខដែលបានស្កេន មិនមែនជា Face ID របស់គណនីនេះឡើយ。'];
            }
        }
    }

    return ['match' => false, 'message' => 'ការផ្ទៀងផ្ទាត់ផ្ទៃមុខមានបញ្ហា៖ ' . $lastError];
}

