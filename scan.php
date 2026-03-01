<?php
session_start();

// ===============================================
//      PART 1: CONFIGURATION & FUNCTIONS
// ===============================================


// ENHANCEMENT: Activate error reporting for debugging
require_once __DIR__ . '/config.php';
ini_set('display_errors', 0);     // <--- FIXED: Stop displaying PHP errors to browser
ini_set('display_startup_errors', 0); // <--- FIXED: Stop displaying PHP errors to browser
error_reporting(E_ALL);

require_once __DIR__ . '/vendor/autoload.php';
require_once __DIR__ . '/webpush_functions.php';

// Enable output compression for faster data transmission
if (!ob_start('ob_gzhandler')) {
    ob_start();
}

// FORCE NO-CACHE: Prevent browser from storing old version of this page
header("Cache-Control: no-cache, no-store, must-revalidate"); // HTTP 1.1.
header("Pragma: no-cache"); // HTTP 1.0.
header("Expires: 0"); // Proxies.

// ===============================================
//  CORS & AUTHORIZATION HEADER SUPPORT (for Mobile/API clients)
// ===============================================
// Allow CORS for API-style requests. Safe default: reflect Origin when provided.
if (isset($_SERVER['HTTP_ORIGIN'])) {
    $origin = $_SERVER['HTTP_ORIGIN'];
    header('Access-Control-Allow-Origin: ' . $origin);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization');
}
// Handle preflight quickly
if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') {
    http_response_code(204);
    exit;
}

// Parse Bearer token from Authorization header to enable token-based API access without cookies
function get_bearer_token_from_headers() {
    $headers = [];
    if (function_exists('getallheaders')) {
        $headers = getallheaders();
    } else {
        // Fallback for environments without getallheaders
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$key] = $value;
            }
        }
    }
    $auth = $headers['Authorization'] ?? $headers['authorization'] ?? '';
    if (stripos($auth, 'Bearer ') === 0) {
        return trim(substr($auth, 7));
    }
    return null;
}

// If Authorization: Bearer <token> is provided, make it available for auto-login flow
$__bearer = get_bearer_token_from_headers();
if ($__bearer) {
    $_SESSION['auth_token'] = $__bearer; // Auto-login section below will resolve the user
}

// Configuration is now loaded from config.php
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($mysqli->connect_error) {
    die("Database Connection Failed: " . $mysqli->connect_error);
}
$mysqli->set_charset("utf8mb4");

// 1. Basic check for users table (self-heal)
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

// 2. Ensure push_subscriptions table exists
$mysqli->query("CREATE TABLE IF NOT EXISTS push_subscriptions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    employee_id VARCHAR(50) NOT NULL,
    endpoint TEXT NOT NULL,
    p256dh VARCHAR(255) NOT NULL,
    auth VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY (endpoint(255))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");




function haversine_distance($lat1, $lon1, $lat2, $lon2) {
    $lat1 = floatval($lat1); $lon1 = floatval($lon1);
    $lat2 = floatval($lat2); $lon2 = floatval($lon2);
    $dLat = deg2rad($lat2 - $lat1); $dLon = deg2rad($lon2 - $lon1);
    $lat1 = deg2rad($lat1); $lat2 = deg2rad($lat2);
    $a = sin($dLat / 2) * sin($dLat / 2) + sin($dLon / 2) * sin($dLon / 2) * cos($lat1) * cos($lat2);
    $c = 2 * atan2(sqrt($a), sqrt(1 - $a));
    return EARTH_RADIUS_KM * $c * 1000;
}

// Dynamic Telegram settings (typed + base overrides)
function get_dynamic_telegram_settings($mysqli) {
    // Typed-aware: try skill/worker variant first (via get_setting_typed), then base admin-specific, then constants
    $bot = get_setting_typed('telegram_bot_token', '');
    if ($bot === '') { $bot = get_setting('telegram_bot_token',''); }
    if ($bot === '') { $bot = TELEGRAM_BOT_TOKEN; }
    $chat = get_setting_typed('telegram_chat_id', '');
    if ($chat === '') { $chat = get_setting('telegram_chat_id',''); }
    if ($chat === '') { $chat = TELEGRAM_CHAT_ID; }

    // Default notification flags: if no explicit setting is found, enable by default when we have a token+chat
    $notifyAttendanceRaw = get_setting_typed('telegram_notify_attendance', null);
    if ($notifyAttendanceRaw === null || $notifyAttendanceRaw === '') { $notifyAttendanceRaw = get_setting('telegram_notify_attendance', null); }
    if ($notifyAttendanceRaw === null || $notifyAttendanceRaw === '') { $notifyAttendanceRaw = ($bot && $chat) ? '1' : '0'; }
    $notifyRequestsRaw = get_setting_typed('telegram_notify_requests', null);
    if ($notifyRequestsRaw === null || $notifyRequestsRaw === '') { $notifyRequestsRaw = get_setting('telegram_notify_requests', null); }
    if ($notifyRequestsRaw === null || $notifyRequestsRaw === '') { $notifyRequestsRaw = ($bot && $chat) ? '1' : '0'; }

    $truthy = ['1','true','yes','on'];
    $notifyAttendance = in_array(strtolower((string)$notifyAttendanceRaw), $truthy, true);
    $notifyRequests  = in_array(strtolower((string)$notifyRequestsRaw), $truthy, true);

    return [
        'bot_token' => $bot,
        'chat_id' => $chat,
        'notify_attendance' => $notifyAttendance,
        'notify_requests' => $notifyRequests
    ];
}

function sendTelegramMessage($mysqli, $message, $type = 'generic') {
    $cfg = get_dynamic_telegram_settings($mysqli);
    $botToken = $cfg['bot_token'];
    $chatId   = $cfg['chat_id'];

    // For legacy types enforce flags; for new forced type always send
    if ($type === 'attendance' && !$cfg['notify_attendance']) {
        error_log('[Telegram] Skipped attendance message (flag off) admin=' . get_current_admin_id($mysqli));
        return false;
    }
    if ($type === 'request' && !$cfg['notify_requests']) {
        error_log('[Telegram] Skipped request message (flag off) admin=' . get_current_admin_id($mysqli));
        return false;
    }
    // attendance_force bypasses flag check

    if (!$botToken || !$chatId || stripos($botToken, 'YOUR_TELEGRAM') !== false) {
        error_log('[Telegram] Skipped: invalid bot/chat configuration bot=' . substr($botToken,0,8) . ' chat=' . $chatId);
        return false;
    }

    $url = 'https://api.telegram.org/bot' . $botToken . '/sendMessage';
    $disablePreviewSetting = strtolower((string)get_setting('telegram_disable_preview', '1'));
    $disablePreview = in_array($disablePreviewSetting, ['1','true','yes','on'], true);
    $payload = http_build_query([
        'chat_id' => $chatId,
        'text' => $message,
        'parse_mode' => 'HTML',
        'disable_web_page_preview' => $disablePreview ? 1 : 0
    ]);
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 5); // Timeout after 5 seconds to avoid blocking
    curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 2); // Connection timeout 2 seconds
    $result = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    if ($result === false) {
        error_log('[Telegram] cURL error: ' . curl_error($ch));
        curl_close($ch);
        return false;
    }
    $decoded = json_decode($result, true);
    $ok  = is_array($decoded) && isset($decoded['ok']) ? ($decoded['ok'] ? 'true' : 'false') : 'n/a';
    $desc = is_array($decoded) && isset($decoded['description']) ? $decoded['description'] : '';
    error_log('[Telegram] Sent type=' . $type . ' admin=' . get_current_admin_id($mysqli) . ' http=' . $httpCode . ' ok=' . $ok . ($desc!==''?(' desc=' . $desc):'') );
    curl_close($ch);
    return $decoded['ok'] ?? false;
}

/**
 * Render template with replacements and strip lines that contain no meaningful text
 * after placeholder replacement (removes label-only lines like "<b>Field:</b> " when value is empty).
 * @param string $template
 * @param array $replacements map of placeholder => replacement (e.g. '{{name}}' => 'John')
 * @return string
 */
function render_template_strip_empty_lines($template, $replacements) {
    // Produce a fully replaced version
    $replaced_full = strtr($template, $replacements);

    // Split original and replaced into lines
    $orig_lines = preg_split('/\r\n|\r|\n/', $template);
    $rep_lines = preg_split('/\r\n|\r|\n/', $replaced_full);
    $out = [];

    foreach ($orig_lines as $i => $orig_line) {
        $rep_line = $rep_lines[$i] ?? '';

        // Find placeholders in the original line
        if (preg_match_all('/\{\{\s*([a-zA-Z0-9_]+)\s*\}\}/', $orig_line, $m)) {
            $keys = $m[1];
            $hasNonEmpty = false;
            foreach ($keys as $k) {
                $ph = '{{' . $k . '}}';
                if (array_key_exists($ph, $replacements) && trim((string)$replacements[$ph]) !== '') {
                    $hasNonEmpty = true;
                    break;
                }
            }
            if ($hasNonEmpty) {
                $out[] = $rep_line;
            } else {
                // all placeholders in this line were empty/missing -> skip the line
                continue;
            }
        } else {
            // no placeholders in this line -> keep the replaced version
            $out[] = $rep_line;
        }
    }

    // Join with LF
    return implode("\n", $out);
}

// Helper: format {{time}} placeholder with support for optional literal suffix
// Admins can type formats like: "d-m-Y h:i A — Phnom Penh" and we will treat
// the right-hand part after the em dash as plain text (no PHP date tokens).
// Supported separators: " — " (em dash surrounded by spaces) or " || "
function format_time_for_placeholder($format) {
    $format = (string)$format;
    $suffix = '';
    // Try em dash first
    if (strpos($format, ' — ') !== false) {
        list($format, $suffix) = explode(' — ', $format, 2);
        $suffix = ' — ' . $suffix; // re-attach delimiter
    } elseif (strpos($format, ' || ') !== false) {
        list($format, $suffix) = explode(' || ', $format, 2);
        $suffix = ' ' . $suffix; // space-prefixed suffix
    }
    // Safe fallback if format accidentally empty
    if (trim($format) === '') { $format = 'Y-m-d H:i:s'; }
    return date($format) . $suffix;
}

// -----------------------------------------------
//  **CRITICAL FIX: Database Connection Check**
// -----------------------------------------------
$mysqli = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

$mysqli->set_charset("utf8mb4");

if ($mysqli->connect_error) {
    // FIX: Ensure a JSON response is sent for AJAX calls if DB fails.
    if (isset($_POST['action'])) {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false,
            'message' => 'កំហុសប្រព័ន្ធ: មិនអាចភ្ជាប់ទៅមូលដ្ឋានទិន្នន័យបានទេ។ សូមពិនិត្យ DB Configuration។' . $mysqli->connect_error
        ]);
        exit;
    } else {
        // For standard page load, show the error
        die("Database Connection Failed: Please check configuration. Error: " . $mysqli->connect_error);
    }
}
// -----------------------------------------------

// START: REWORKED APP SCAN SETTINGS (Scope by Admin / User Group)
// Purpose: Ensure settings do not mix between different normal users under different admins.
// Strategy: Resolve the owning Admin ID for the current user and fetch settings for that admin.
//           Fallback to 'SYSTEM_WIDE' when an admin-specific key is not found.

/**
 * Resolve the Admin ID whose settings should apply to the current session/user.
 * Rules:
 * - If current user is an Admin, use their employee_id as admin_id
 * - If current user is a Normal user, use created_by_admin_id
 * - If not logged in or lookup fails, use 'SYSTEM_WIDE'
 */
function get_current_admin_id($mysqli) {
    // Compute the effective admin id fresh on every call (no session caching)
    static $current_admin_id_cache = null;
    if ($current_admin_id_cache !== null) return $current_admin_id_cache;

    $employee_id = $_SESSION['employee_id'] ?? null;
    if (!$employee_id) {
        return 'SYSTEM_WIDE';
    }

    $admin_id = 'SYSTEM_WIDE';
    $sql = "SELECT user_role, COALESCE(created_by_admin_id, '') AS created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $employee_id);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($row = $res->fetch_assoc()) {
            if (strcasecmp($row['user_role'] ?? '', 'Admin') === 0) {
                $admin_id = $employee_id;
            } else {
                $admin_id = ($row['created_by_admin_id'] !== '') ? $row['created_by_admin_id'] : 'SYSTEM_WIDE';
            }
        }
        $stmt->close();
    }
    $current_admin_id_cache = $admin_id;
    return $admin_id;
}

/**
 * Get an App Scan setting for the resolved admin scope, with SYSTEM_WIDE fallback.
 */
function get_setting($key, $default = '') {
    global $mysqli;
    static $cache = [];
    $adminId = get_current_admin_id($mysqli);
    $ck = $adminId . '|' . $key;
    if (array_key_exists($ck, $cache)) return $cache[$ck];

    // 1) Try admin-specific value (prefer most recent row if duplicates exist)
    if ($stmt = $mysqli->prepare("SELECT setting_value FROM app_scan_settings WHERE admin_id = ? AND setting_key = ? ORDER BY id DESC LIMIT 1")) {
        $stmt->bind_param("ss", $adminId, $key);
        $stmt->execute();
        $res = $stmt->get_result();
        if ($res && ($row = $res->fetch_assoc())) {
            $cache[$ck] = $row['setting_value'];
            $stmt->close();
            return $cache[$ck];
        }
        $stmt->close();
    }

    // 2) Fallback to SYSTEM_WIDE (prefer most recent row)
    if ($stmt2 = $mysqli->prepare("SELECT setting_value FROM app_scan_settings WHERE admin_id = 'SYSTEM_WIDE' AND setting_key = ? ORDER BY id DESC LIMIT 1")) {
        $stmt2->bind_param("s", $key);
        $stmt2->execute();
        $res2 = $stmt2->get_result();
        if ($res2 && ($row2 = $res2->fetch_assoc())) {
            $cache[$ck] = $row2['setting_value'];
            $stmt2->close();
            return $cache[$ck];
        }
        $stmt2->close();
    }

    // 3) Default
    $cache[$ck] = $default;
    return $default;
}
// END: REWORKED APP SCAN SETTINGS


// ===============================================
//   Typed settings helper (per selected user type)
//   Usage: stores type in $_SESSION['scan_user_type'] as 'skill'|'worker'
//   Looks up key with suffix "__skill" or "__worker" first, then falls back to base key
// ===============================================
// ===============================================
//   Typed settings helper (per selected user type)
//   Usage: stores type in $_SESSION['scan_user_type'] as 'skill'|'worker'
//   Looks up key with suffix "__skill" or "__worker" first, then falls back to base key
// ===============================================
function get_setting_typed($key, $default = '') {
    $t = strtolower($_SESSION['scan_user_type'] ?? '');
    if ($t === 'skill' || $t === 'worker') {
        $typedKey = $key . '__' . $t;
        $val = get_setting($typedKey, null);
        if ($val !== null && $val !== '') return $val;
    }
    return get_setting($key, $default);
}

/**
 * Check if Manual Scan is allowed for the current logged-in user.
 * Checks 'manual_scan_mode' (all/specific/disabled) and 'manual_scan_specific_users'.
 * @return bool
 */
function is_manual_scan_allowed() {
    // 1. Check global mode ('all', 'specific', 'disabled' or old boolean '0'/'1' fallback)
    $mode = get_setting_typed('manual_scan_mode', 'disabled');

    // Fallback for transition: if user had old boolean 'manual_scan_enabled' set to '1' but no mode set
    if ($mode === 'disabled') {
        $old_enabled = get_setting_typed('manual_scan_enabled', '0');
        if ($old_enabled === '1') { $mode = 'all'; }
    }

    if ($mode === 'disabled') return false;
    if ($mode === 'all') return true;

    if ($mode === 'specific') {
        $current_id = $_SESSION['employee_id'] ?? '';
        if ($current_id === '') return false;

        $allowed_list_str = get_setting_typed('manual_scan_specific_users', '');
        $allowed_ids = array_map('trim', explode(',', $allowed_list_str));
        // Simple case-insensitive check
        foreach ($allowed_ids as $id) {
            if (strcasecmp($id, $current_id) === 0) return true;
        }
    }
    return false;
}

// ===============================================
//  Department allow-list validation helper
//  Normalizes department text and compares against normalized allowed list.
//  Returns [bool allowed, string normalized_department, array normalized_allowed]
// ===============================================
function department_allowed_for_type($scanType, $rawDepartment) {
    $scanType = strtolower(trim($scanType ?? ''));
    $norm = preg_replace('/\s+/u', ' ', trim((string)$rawDepartment));
    $normLower = mb_strtolower($norm, 'UTF-8');

    $allowedSkillRaw  = get_setting('allowed_departments_skill', '');
    $allowedWorkerRaw = get_setting('allowed_departments_worker', '');

    $explodeAndNormalize = function($csv) {
        $out = [];
        foreach (explode(',', (string)$csv) as $piece) {
            $p = preg_replace('/\s+/u', ' ', trim($piece));
            if ($p !== '') { $out[$p] = mb_strtolower($p, 'UTF-8'); }
        }
        return $out;
    };

    $allowedSkill  = $explodeAndNormalize($allowedSkillRaw);
    $allowedWorker = $explodeAndNormalize($allowedWorkerRaw);

    $activeMap = ($scanType === 'skill') ? $allowedSkill : (($scanType === 'worker') ? $allowedWorker : []);
    $otherMap  = ($scanType === 'skill') ? $allowedWorker : $allowedSkill;

    // NEW STRICT LOGIC:
    // 1. If both lists empty => allow all (no policy configured).
    // 2. If active list empty but other list has entries => deny (means this type intentionally has no allowed departments).
    // 3. Otherwise require membership in active list.
    if (empty($allowedSkill) && empty($allowedWorker)) {
        return [true, $norm, []];
    }
    if (empty($activeMap) && !empty($otherMap)) {
        return [false, $norm, []];
    }

    $isAllowed = in_array($normLower, $activeMap, true);
    return [$isAllowed, $norm, array_keys($activeMap)];
}


// ===============================================
//        PART 2: AJAX REQUEST HANDLER (CUSTOM GD BACKGROUND REMOVAL & SAVE)
// ===============================================

// ===============================================
//  PART 2.0: API LOGIN (JSON) for Mobile Clients
//  POST: action=api_login, employee_id=<ID>
//  Response: { success: bool, message?: string, token?: string, user?: { id, name } }
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'api_login') {
    header('Content-Type: application/json');
    $resp = ['success' => false, 'message' => 'Invalid request'];

    $employee_id = trim($_POST['employee_id'] ?? '');
    $scan_user_type = strtolower(trim($_POST['scan_user_type'] ?? ''));
    if ($employee_id === '') {
        echo json_encode(['success' => false, 'message' => 'Employee ID is required.']);
        exit;
    }

    // Look up user and max token policy (reuse logic from form-login)
    $sql = "SELECT u.employee_id, u.name, u.custom_data,\r\n                 COALESCE(\r\n                     a.global_max_tokens,\r\n                     (SELECT global_max_tokens FROM users WHERE user_role = 'Admin' AND created_by_admin_id IS NULL LIMIT 1),\r\n                     1\r\n                 ) AS max_tokens_allowed\r\n             FROM users u\r\n             LEFT JOIN users a ON a.employee_id = u.created_by_admin_id AND a.user_role = 'Admin'\r\n             WHERE u.employee_id = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param('s', $employee_id);
        $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows == 1) {
            $user_db = $result->fetch_assoc();
            $max_tokens = (int)($user_db['max_tokens_allowed'] ?? 1);

            // Optional: Department check if caller provides scan_user_type
            if ($scan_user_type === 'skill' || $scan_user_type === 'worker') {
                $cd = json_decode($user_db['custom_data'] ?? '{}', true) ?: [];
                $deptVal = $cd['department'] ?? $cd['workplace'] ?? $cd['workplace_name'] ?? $cd['នាយកដ្ឋាន'] ?? '';
                list($okDept, $normDept) = department_allowed_for_type($scan_user_type, $deptVal);
                if (!$okDept) {
                    echo json_encode(['success' => false, 'message' => 'Department not allowed for selected type.']);
                    $stmt->close();
                    exit;
                }
            }

            // Count current tokens
            if ($cnt = $mysqli->prepare('SELECT COUNT(*) FROM active_tokens WHERE employee_id = ?')) {
                $cnt->bind_param('s', $employee_id);
                $cnt->execute();
                $active_count = (int)($cnt->get_result()->fetch_row()[0] ?? 0);
                $cnt->close();
            } else { $active_count = 0; }

            if ($active_count >= $max_tokens) {
                echo json_encode(['success' => false, 'message' => 'Token limit exceeded for this user.']);
                $stmt->close();
                exit;
            }

            $new_token = bin2hex(random_bytes(32));
            if ($ins = $mysqli->prepare('INSERT INTO active_tokens (employee_id, auth_token) VALUES (?, ?)')) {
                $ins->bind_param('ss', $employee_id, $new_token);
                if ($ins->execute()) {
                    echo json_encode([
                        'success' => true,
                        'token' => $new_token,
                        'user' => [
                            'id' => $user_db['employee_id'],
                            'name' => $user_db['name']
                        ]
                    ]);
                    $ins->close();
                    $stmt->close();
                    exit;
                }
                $ins->close();
            }
            $resp = ['success' => false, 'message' => 'Failed to create token.'];
        } else {
            $resp = ['success' => false, 'message' => 'User not found.'];
        }
        $stmt->close();
    } else {
        $resp = ['success' => false, 'message' => 'DB error: ' . $mysqli->error];
    }
    echo json_encode($resp);
    exit;
}

// Helper function to remove white background using PHP GD
function remove_white_background($base64_image) {
    global $mysqli; // Use the connection established above

    // Check if GD is available first
    if (!extension_loaded('gd')) {
        return ['success' => false, 'message' => 'PHP GD extension is not loaded.'];
    }

    if (preg_match('/^data:image\/(png|jpeg|gif);base64,([a-zA-Z0-9\+\/]+={0,2})$/', $base64_image, $matches)) {
        $image_binary = base64_decode($matches[2]);
    } else {
        return ['success' => false, 'message' => 'Invalid image format.'];
    }

    // Check for potential GD issue
    if (strpos($image_binary, '<?php') !== false) {
        return ['success' => false, 'message' => 'Security Error: Invalid image data detected.'];
    }

    $img = @imagecreatefromstring($image_binary);
    if ($img === false) {
        return ['success' => false, 'message' => 'Failed to create image resource from data (Possible unsupported format or corrupt data).'];
    }

    imagealphablending($img, false);
    imagesavealpha($img, true);

    // Increased Tolerance to handle off-white/gray paper (40 is a good starting point)
    $tolerance = 40;
    $white_threshold = 255 - $tolerance;

    $width = imagesx($img);
    $height = imagesy($img);

    for ($x = 0; $x < $width; $x++) {
        for ($y = 0; $y < $height; $y++) {
            $color = imagecolorat($img, $x, $y);
            $r = ($color >> 16) & 0xFF;
            $g = ($color >> 8) & 0xFF;
            $b = $color & 0xFF;

            // Check if all color components are above the threshold (i.e., close to white/off-white)
            if ($r >= $white_threshold && $g >= $white_threshold && $b >= $white_threshold) {
                // Set the pixel to fully transparent (alpha=127)
                $transparent_color = imagecolorallocatealpha($img, 0, 0, 0, 127);
                imagesetpixel($img, $x, $y, $transparent_color);
            }
        }
    }

    ob_start();
    $final_mime = 'image/png';
    if (function_exists('imagewebp')) {
        imagewebp($img, null, 80); // 80 quality is great for signatures
        $final_mime = 'image/webp';
    } else {
        imagepng($img);
    }
    $binary = ob_get_clean();
    imagedestroy($img);

    $base64 = 'data:' . $final_mime . ';base64,' . base64_encode($binary);

    return [
        'success' => true,
        'filePath' => $base64
    ];
}


if (isset($_POST['action']) && $_POST['action'] === 'upload_signature') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'An unknown error occurred during signature upload.'];

    if (!isset($_SESSION['employee_id'])) {
        $response['message'] = 'User not authenticated. Please login again.';
        echo json_encode($response);
        exit;
    }

    $base64_data = $_POST['signature_base64'] ?? null;
    $employee_id = $_SESSION['employee_id'];

    if ($base64_data && is_string($base64_data)) {
        if (preg_match('/^data:image\/(png|jpeg|gif);base64,([a-zA-Z0-9\+\/]+={0,2})$/', $base64_data)) {

            // Check approximate size (Base64 is ~1.33x binary size)
            if (strlen($base64_data) > 5 * 1024 * 1024 * 1.5) {
                 $response['message'] = 'ទិន្នន័យរូបភាពធំពេក។ ទំហំអតិបរមា 5MB (Binary size).';
            } else {
                 $result = remove_white_background($base64_data);

                 if ($result['success']) {
                      // *** NEW: Save Processed Signature to History ***
                      $signature_base64_final = $result['filePath'];
                      // FIX: Use LONGTEXT field if signature is large (over 65KB). Ensure DB column is large enough.
                      $insert_sql = "INSERT INTO signature_history (employee_id, signature_base64) VALUES (?, ?)";

                      if ($stmt_insert = $mysqli->prepare($insert_sql)) {
                          $stmt_insert->bind_param("ss", $employee_id, $signature_base64_final);

                          if ($stmt_insert->execute()) {
                              // Delete oldest signatures if count > 5 (Cleanup)
                              $delete_old_sql = "DELETE FROM signature_history WHERE employee_id = ? AND created_at < (SELECT MIN(created_at) FROM (SELECT created_at FROM signature_history WHERE employee_id = ? ORDER BY created_at DESC LIMIT 5) AS T)";
                              if ($stmt_delete = $mysqli->prepare($delete_old_sql)) {
                                  $stmt_delete->bind_param("ss", $employee_id, $employee_id);
                                  $stmt_delete->execute();
                                  $stmt_delete->close();
                              }

                              $response = [
                                  'success' => true,
                                  'message' => 'ហត្ថលេខាត្រូវបានកាត់ផ្ទៃខាងក្រោយដោយជោគជ័យ និងរក្សាទុក!',
                                  'filePath' => $signature_base64_final
                              ];
                          } else {
                              $response['message'] = 'GD ជោគជ័យ ប៉ុន្តែរក្សាទុក DB បរាជ័យ៖ ' . $stmt_insert->error;
                          }
                          $stmt_insert->close();
                      } else {
                          // FIX: Added error logging for DB prepare failure
                           $response['message'] = 'កំហុស Prepared Statement (Save History): ' . $mysqli->error;
                      }
                      // *** END NEW SAVE LOGIC ***
                 } else {
                      $response['message'] = 'កំហុសពេលដំណើរការរូបភាព: ' . ($result['message'] ?? 'Unknown GD error.');
                 }
            }
        } else {
            $response['message'] = 'ទម្រង់រូបភាពមិនត្រឹមត្រូវ។';
        }
    } else {
        $response['message'] = 'មិនបានទទួលទិន្នន័យរូបភាពទេ។';
    }

    echo json_encode($response);
    exit;
}

// ===============================================
//        PART 7: FETCH SIGNATURE HISTORY
// ===============================================

if (isset($_POST['action']) && $_POST['action'] === 'fetch_signature_history') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'data' => []];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];
        // Get the latest 5 signatures
        $sql = "SELECT id, signature_base64, created_at FROM signature_history
                 WHERE employee_id = ?
                 ORDER BY created_at DESC
                 LIMIT 5";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $employee_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $signatures = [];

            while ($row = $result->fetch_assoc()) {
                $signatures[] = [
                    'id' => $row['id'],
                    'base64' => $row['signature_base64'],
                    'date' => date('d-M-Y H:i', strtotime($row['created_at']))
                ];
            }
            $stmt->close();

            $response['success'] = true;
            $response['message'] = 'Successfully fetched signature history.';
            $response['data'] = $signatures;

        } else {
            $response['message'] = "Database query error: " . $mysqli->error;
        }
    }

    echo json_encode($response);
    exit;
}

// ===============================================
//        PART 8: FETCH LAST ATTENDANCE ACTION (NEW CODE FOR AUTO-SELECT)
// ===============================================

if (isset($_POST['action']) && $_POST['action'] === 'fetch_last_action') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'last_action' => 'Check-Out']; // Default to Check-Out (suggest Check-In)

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];

        // Get the latest check-in/out record for today
        $today_start = date('Y-m-d 00:00:00');
        $sql = "SELECT action_type FROM checkin_logs
                WHERE employee_id = ?
                AND log_datetime >= ?
                ORDER BY log_datetime DESC
                LIMIT 1";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("ss", $employee_id, $today_start);
            $stmt->execute();
            $result = $stmt->get_result();

            $last_action = 'Check-Out'; // Default: If no log found today, the last action was 'Check-Out' yesterday.

            if ($row = $result->fetch_assoc()) {
                $last_action = $row['action_type'];
            }

            $stmt->close();

            $response['success'] = true;
            // Send the LAST action performed. Frontend will calculate the NEXT suggested action.
            $response['last_action'] = $last_action;
        } else {
            $response['message'] = "Database query preparation error: " . $mysqli->error;
        }
    }

    echo json_encode($response);
    exit;
}


// ===============================================
//        PART 9: USER NOTIFICATIONS
// ===============================================

if (isset($_POST['ajax_action']) && $_POST['ajax_action'] === 'get_user_notifications') {
    header('Content-Type: application/json');
    $response = ['status' => 'error', 'message' => 'User not authenticated.'];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];

        // Create tables if not exist
        $mysqli->query("CREATE TABLE IF NOT EXISTS notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            admin_id VARCHAR(64) NOT NULL,
            title VARCHAR(255) NOT NULL,
            message TEXT NOT NULL,
            recipient_type ENUM('all', 'specific', 'group') NOT NULL,
            recipient_info TEXT,
            sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            expiry_date DATETIME NULL,
            status ENUM('sent', 'expired') DEFAULT 'sent'
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        $mysqli->query("CREATE TABLE IF NOT EXISTS user_notifications (
            id INT AUTO_INCREMENT PRIMARY KEY,
            notification_id INT NOT NULL,
            employee_id VARCHAR(64) NOT NULL,
            is_read TINYINT(1) DEFAULT 0,
            read_at TIMESTAMP NULL,
            FOREIGN KEY (notification_id) REFERENCES notifications(id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci");

        // Get user's notifications
        $sql = "SELECT n.id, n.title, n.message, n.sent_at, un.is_read, un.read_at
                FROM user_notifications un
                JOIN notifications n ON un.notification_id = n.id
                WHERE un.employee_id = ?
                AND (n.expiry_date IS NULL OR n.expiry_date > NOW())
                ORDER BY n.sent_at DESC
                LIMIT 50";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $employee_id);
            $stmt->execute();
            $result = $stmt->get_result();

            $notifications = [];
            $unread_count = 0;
            $total_count = 0;
            while ($row = $result->fetch_assoc()) {
                $notifications[] = [
                    'id' => $row['id'],
                    'title' => $row['title'],
                    'message' => $row['message'],
                    'sent_at' => date('d/m/Y H:i', strtotime($row['sent_at'])),
                    'is_read' => (bool)$row['is_read']
                ];
                $total_count++;
                if (!$row['is_read']) {
                    $unread_count++;
                }
            }
            $stmt->close();

            $response = ['status' => 'success', 'notifications' => $notifications, 'unread_count' => $unread_count, 'total_count' => $total_count];
        } else {
            $response = ['status' => 'error', 'message' => 'Database query error.'];
        }
    }

    echo json_encode($response);
    exit;
}

if (isset($_POST['ajax_action']) && $_POST['ajax_action'] === 'mark_notification_read') {
    header('Content-Type: application/json');
    $response = ['status' => 'error', 'message' => 'User not authenticated.'];

    if (isset($_SESSION['employee_id']) && isset($_POST['notification_id'])) {
        $employee_id = $_SESSION['employee_id'];
        $notification_id = (int)$_POST['notification_id'];

        $sql = "UPDATE user_notifications
                SET is_read = 1, read_at = NOW()
                WHERE notification_id = ? AND employee_id = ?";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("is", $notification_id, $employee_id);
            if ($stmt->execute()) {
                $response = ['status' => 'success'];
            } else {
                $response = ['status' => 'error', 'message' => 'Failed to mark as read.'];
            }
            $stmt->close();
        } else {
            $response = ['status' => 'error', 'message' => 'Database error.'];
        }
    }

    echo json_encode($response);
    exit;
}

// ===============================================
//        END USER NOTIFICATIONS
// ===============================================


// ===============================================
//        PART 3: REQUEST FORM HANDLER (MODIFIED TO USE NEW COLUMNS)
// ===============================================

// Check if user is trying to submit a request form (AJAX Call)
if (isset($_POST['action']) && $_POST['action'] === 'submit_request') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'កំហុស: មិនអាចដំណើរការសំណើបានទេ។'];

    if (!isset($_SESSION['employee_id'])) {
        $response['message'] = 'User not authenticated. Please login again.';
        echo json_encode($response);
        exit;
    }

    if (!isset($_POST['requestType']) || !isset($_POST['formDataJson'])) {
        $response['message'] = 'ទិន្នន័យសំណើមិនពេញលេញទេ។';
        echo json_encode($response);
        exit;
    }

    $request_type = trim($_POST['requestType']);
    $employee_id = $_SESSION['employee_id'];
    $name = '';

    $request_date = date('Y-m-d H:i:s');
    $form_data_json = $_POST['formDataJson']; // Raw JSON from frontend
    $request_status = 'Pending';

    $form_data_array = json_decode($form_data_json, true);

    // ================== START: MAP FORM DATA TO NEW DB COLUMNS ==================

    // 1. Initialize all specific fields to NULL
    $event_date = $event_start_time = $event_end_time = $contact_number = NULL;
    $leave_makeup_date = $leave_makeup_hours = $leave_total_hours = $leave_handoff_to = NULL;
    $forget_type = $forgot_count = $original_day_off = $new_work_day = $new_day_off = NULL;
    $reason_detail = ''; // Will be set later, is NOT NULL in new schema.
    $signature_path = NULL;

    // 2. Determine Signature Path Key
    $signature_field_key = '';
    if($request_type === 'Leave') $signature_field_key = 'signature_path_leave';
    else if($request_type === 'Overtime') $signature_field_key = 'signature_path_overtime';
    else if($request_type === 'Forget-Attendance') $signature_field_key = 'signature_path_forget';
    else if($request_type === 'Late') $signature_field_key = 'signature_path_late';
    else if($request_type === 'Change-Day-Off') $signature_field_key = 'signature_path_cdo';

    $signature_path = $form_data_array[$signature_field_key] ?? NULL;

    // 3. Map Data based on Request Type
    if ($request_type === 'Leave') {
        $event_date = $form_data_array['leave_date'] ?? NULL;
        $reason_detail = $form_data_array['leave_reason'] ?? '';
        $contact_number = $form_data_array['leave_contact'] ?? NULL;
        $leave_makeup_date = $form_data_array['leave_makeup_date'] ?? NULL;
        $leave_makeup_hours = $form_data_array['leave_makeup_hours'] ?? NULL;
        $leave_total_hours = $form_data_array['leave_total_hours'] ?? NULL;
        $leave_handoff_to = $form_data_array['leave_handoff'] ?? NULL;

    } else if ($request_type === 'Overtime') {
        $event_date = $form_data_array['ot_date'] ?? NULL;
        $event_start_time = $form_data_array['ot_start_time'] ?? NULL;
        $event_end_time = $form_data_array['ot_end_time'] ?? NULL;
        $reason_detail = $form_data_array['ot_reason'] ?? '';

    } else if ($request_type === 'Forget-Attendance') {
        $event_date = $form_data_array['forget_date'] ?? NULL;
        $forget_type = $form_data_array['forgetType'] ?? NULL;
        $event_start_time = $form_data_array['forget_check_in_time'] ?? NULL;
        $event_end_time = $form_data_array['forget_check_out_time'] ?? NULL;
        $forgot_count = $form_data_array['forgot_count'] ?? NULL;
        $reason_detail = $form_data_array['forget_reason'] ?? '';

    } else if ($request_type === 'Late') {
        $event_date = $form_data_array['late_date'] ?? NULL;
        $event_start_time = $form_data_array['actual_check_in_time'] ?? NULL;
        $reason_detail = $form_data_array['late_reason_text'] ?? '';

    } else if ($request_type === 'Change-Day-Off') {
        $reason_detail = $form_data_array['change_day_off_reason'] ?? '';
        $original_day_off = $form_data_array['original_day_off'] ?? NULL;
        $new_work_day = $form_data_array['new_work_day'] ?? NULL;
        $new_day_off = $form_data_array['new_day_off'] ?? NULL;
    }

    // Ensure reason_detail is not empty (since DB column is NOT NULL)
    if (empty($reason_detail)) {
        $reason_detail = "N/A - Request Type: " . $request_type;
    }

    // Generate human-readable summary for Telegram/Logging (reusing old logic, slightly modified)
    $request_summary_text = '';
    if (is_array($form_data_array)) {
        $summary_parts = [];
        // Use a simpler map for Telegram as the DB no longer needs to rely on this logic
        foreach ($form_data_array as $key => $value) {
            if (strpos($key, 'signature_path') === false && !empty($value)) {
                $label = ucwords(str_replace(['_', 'Date', 'Time'], [' ', ' ថ្ងៃ', ' ម៉ោង'], $key));
                $summary_parts[] = "{$label}: {$value}";
            }
        }
        $request_summary_text = implode("\n", $summary_parts);
    }

    // =================== END: MAP FORM DATA TO NEW DB COLUMNS ===================


    // Re-fetch user name (unchanged logic)
    $name_sql = "SELECT name FROM users WHERE employee_id = ?";
    if ($stmt_name = $mysqli->prepare($name_sql)) {
           $stmt_name->bind_param("s", $employee_id); $stmt_name->execute();
           $result_name = $stmt_name->get_result();
           if ($result_name->num_rows == 1) $name = $result_name->fetch_assoc()['name'];
           $stmt_name->close();
    }

    if (empty($name)) {
        $response['message'] = 'កំហុស: រកមិនឃើញឈ្មោះបុគ្គលិកទេ។';
        echo json_encode($response);
        exit;
    }

    // **MODIFIED SQL STATEMENT (New Denormalized Schema)**
    $insert_sql = "INSERT INTO requests_logs (
        employee_id, name, request_type, request_status, submitted_at, signature_path,
        event_date, event_start_time, event_end_time, reason_detail, contact_number,
        leave_makeup_date, leave_makeup_hours, leave_total_hours, leave_handoff_to,
        forget_type, forgot_count, original_day_off, new_work_day, new_day_off
    ) VALUES (
        ?, ?, ?, ?, ?, ?,
        ?, ?, ?, ?, ?,
        ?, ?, ?, ?,
        ?, ?, ?, ?, ?
    )";

    if ($stmt_insert = $mysqli->prepare($insert_sql)) {
        // **MODIFIED BIND PARAMETERS** (20 parameters for 20 columns)
        // Using 's' for most columns as they come from form input and MySQL can handle conversion
        $stmt_insert->bind_param("ssssssssssssssssssss",
            $employee_id, $name, $request_type, $request_status, $request_date, $signature_path,
            $event_date, $event_start_time, $event_end_time, $reason_detail, $contact_number,
            $leave_makeup_date, $leave_makeup_hours, $leave_total_hours, $leave_handoff_to,
            $forget_type, $forgot_count, $original_day_off, $new_work_day, $new_day_off
        );

        if ($stmt_insert->execute()) {
            $response['success'] = true;
            $response['message'] = "ការស្នើសុំ{$request_type}ត្រូវបានដាក់ស្នើជោគជ័យ! រង់ចាំការអនុម័ត។";

            // --- Send Telegram Notification ---
            // Build request telegram message from template
            $tpl = get_setting('telegram_tpl_request', '<b>[NEW REQUEST]</b>\n<b>ប្រភេទ:</b> {{request_type}}\n<b>ឈ្មោះ:</b> {{name}}\n<b>ID:</b> {{employee_id}}\n<b>ព័ត៌មានលម្អិត:</b> {{summary}}\n<b>ម៉ោង:</b> {{time}}');
            // Format time according to admin-configurable setting (supports literal suffix)
            $time_format = get_setting('telegram_time_format', 'Y-m-d H:i:s');
            $formatted_time = format_time_for_placeholder($time_format);
            $replacements = [
                '{{request_type}}' => htmlspecialchars($request_type),
                '{{name}}' => htmlspecialchars($name),
                '{{employee_id}}' => htmlspecialchars($employee_id),
                '{{summary}}' => htmlspecialchars($request_summary_text),
                '{{time}}' => $formatted_time
            ];
            // Dynamic custom fields: allow placeholders {{field_<key>}} from users.custom_data (loaded earlier into $custom_data)
            if (isset($custom_data) && is_array($custom_data)) {
                foreach ($custom_data as $cKey => $cVal) {
                    if (!is_scalar($cVal)) continue;
                    // Normalize keys: allow stored keys that may already include the 'field_' prefix
                    $norm = (strpos($cKey, 'field_') === 0) ? substr($cKey, 6) : $cKey;
                    $ph = '{{field_' . $norm . '}}';
                    // If the template uses the normalized placeholder, map it
                    if (strpos($tpl, $ph) !== false) {
                        $replacements[$ph] = htmlspecialchars((string)$cVal);
                    }
                    // Also support templates that (for whatever reason) reference the raw key directly
                    $phRaw = '{{' . $cKey . '}}';
                    if (strpos($tpl, $phRaw) !== false) {
                        $replacements[$phRaw] = htmlspecialchars((string)$cVal);
                    }
                }
            }
            $telegram_msg = render_template_strip_empty_lines($tpl, $replacements);
            sendTelegramMessage($mysqli, $telegram_msg, 'request');
            $admin_id_to_notify = get_current_admin_id($mysqli);
            sendWebPushNotification($mysqli, $admin_id_to_notify, "New Request: {$request_type}", strip_tags(str_replace('\n', "\n", $telegram_msg)));
            // ---------------------------------

        } else {
            $response['message'] = "កំហុសពេលបញ្ចូល DB: " . $stmt_insert->error;
            error_log("DB INSERT ERROR for request: " . $stmt_insert->error);
        }
        $stmt_insert->close();
    } else {
           $response['message'] = "កំហុស Prepared Statement: " . $mysqli->error;
           error_log("DB PREPARE ERROR: " . $mysqli->error);
    }

    echo json_encode($response);
    exit;
}

// ===============================================
//        PART 6: FETCH REQUEST LOGS (MODIFIED TO USE NEW COLUMNS)
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'fetch_requests') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'data' => []];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];

        // **MODIFIED SQL STATEMENT**
        $sql = "SELECT
            request_type, request_status, submitted_at,
            event_date, event_start_time, event_end_time,
            reason_detail, forget_type,
            original_day_off, new_day_off,
            leave_makeup_date, leave_total_hours
        FROM requests_logs
        WHERE employee_id = ?
        ORDER BY submitted_at DESC
        LIMIT 20";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $employee_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $requests = [];

            while ($row = $result->fetch_assoc()) {
                // **MODIFIED:** Construct readable summary from the fetched columns
                $request_type = $row['request_type'];
                $reason_detail = $row['reason_detail'] ?? '';
                $reason_summary = $request_type; // Default summary

                if ($request_type === 'Leave') {
                    $date = $row['event_date'] ?? 'N/A';
                    $hours = $row['leave_total_hours'] ?? 'N/A';
                    $reason_summary = "{$date} ({$hours}h) - {$reason_detail}";
                } else if ($request_type === 'Overtime') {
                    $date = $row['event_date'] ?? 'N/A';
                    $start = $row['event_start_time'] ?? 'N/A';
                    $end = $row['event_end_time'] ?? 'N/A';
                    $reason_summary = "OT {$date} @ {$start}-{$end}";
                } else if ($request_type === 'Forget-Attendance') {
                    $date = $row['event_date'] ?? 'N/A';
                    $type = $row['forget_type'] ?? 'Forget';
                    $reason_summary = "{$type} on {$date} - {$reason_detail}";
                } else if ($request_type === 'Late') {
                    $date = $row['event_date'] ?? 'N/A';
                    $time = $row['event_start_time'] ?? 'N/A';
                    $reason_summary = "Late {$date} @ {$time} - {$reason_detail}";
                } else if ($request_type === 'Change-Day-Off') {
                    $original = $row['original_day_off'] ?? 'N/A';
                    $new = $row['new_day_off'] ?? 'N/A';
                    $reason_summary = "CDO {$original} -> {$new}";
                }

                $requests[] = [
                    'type' => $request_type,
                    'status' => $row['request_status'],
                    'reason_summary' => mb_substr(htmlspecialchars($reason_summary), 0, 30) . (mb_strlen($reason_summary) > 30 ? '...' : ''),
                    'date' => date('d-M-Y', strtotime($row['submitted_at']))
                ];
            }
            $stmt->close();

            $response['success'] = true;
            $response['message'] = 'Successfully fetched request logs.';
            $response['data'] = $requests;

        } else {
            $response['message'] = "Database query preparation error: " . $mysqli->error;
        }
    }

    echo json_encode($response);
    exit; // Crucial: Stop script execution to prevent rendering HTML
}

// ===============================================
//   PART 6.5: FETCH REQUEST COUNTS (AJAX for Real-time Update) - កូដបន្ថែមថ្មី
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'fetch_request_counts') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'data' => ['Pending' => 0, 'Approved' => 0, 'Rejected' => 0]];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];
        $request_counts_ajax = ['Pending' => 0, 'Approved' => 0, 'Rejected' => 0];

        $sql_counts = "SELECT request_status, COUNT(*) as count FROM requests_logs WHERE employee_id = ? GROUP BY request_status";
        if ($stmt_counts = $mysqli->prepare($sql_counts)) {
            $stmt_counts->bind_param("s", $employee_id);
            $stmt_counts->execute();
            $result_counts = $stmt_counts->get_result();
            while ($row = $result_counts->fetch_assoc()) {
                if (isset($request_counts_ajax[$row['request_status']])) {
                    $request_counts_ajax[$row['request_status']] = (int)$row['count'];
                }
            }
            $stmt_counts->close();
            $response['success'] = true;
            $response['message'] = 'Successfully fetched counts.';
            $response['data'] = $request_counts_ajax;
        } else {
            $response['message'] = "Database query error: " . $mysqli->error;
        }
    }

    echo json_encode($response);
    exit;
}


// ===============================================
//        PART X: FETCH LATEST SCAN (AJAX for Live Alerts)
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'fetch_latest_scan') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'data' => []];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];

        // Determine if the table has a numeric primary key column we can use (commonly `id`)
        $hasId = false;
        if ($colRes = $mysqli->query("SHOW COLUMNS FROM checkin_logs LIKE 'id'")) {
            $hasId = ($colRes->num_rows > 0);
            $colRes->close();
        }

        // Build a portable query that works even when `id` column is absent
        if ($hasId) {
            $sql_latest = "SELECT id, action_type, log_datetime, status, location_name, distance_m FROM checkin_logs WHERE employee_id = ? ORDER BY id DESC LIMIT 4";
        } else {
            $sql_latest = "SELECT action_type, log_datetime, status, location_name, distance_m FROM checkin_logs WHERE employee_id = ? ORDER BY log_datetime DESC LIMIT 4";
        }

        if ($stmt_latest = $mysqli->prepare($sql_latest)) {
            $stmt_latest->bind_param("s", $employee_id);
            $stmt_latest->execute();
            $result_latest = $stmt_latest->get_result();
            $rows = [];
            while ($r = $result_latest->fetch_assoc()) {
                if (!$hasId) {
                    $r['id'] = strtotime($r['log_datetime']) ?: time();
                }
                $rows[] = $r;
            }
            if (!empty($rows)) {
                $response['success'] = true;
                $response['message'] = 'Latest scans fetched.';
                $response['data'] = $rows;
            }
            $stmt_latest->close();
        }
    }
    echo json_encode($response);
    exit;
}



// ===============================================
//        PART X+2: FETCH LOCATIONS (AJAX for Manual Attendance)
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'fetch_locations') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'data' => []];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];

        // Get the admin who created this user
        $admin_sql = "SELECT COALESCE(created_by_admin_id, '') AS created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1";
        $created_by_admin_id = '';
        if ($admin_stmt = $mysqli->prepare($admin_sql)) {
            $admin_stmt->bind_param("s", $employee_id);
            $admin_stmt->execute();
            $admin_result = $admin_stmt->get_result();
            if ($admin_row = $admin_result->fetch_assoc()) {
                $created_by_admin_id = $admin_row['created_by_admin_id'];
            }
            $admin_stmt->close();
        }

        // Fetch locations created by the same admin, including radius and assignment status
        $sql = "SELECT l.id, l.location_name, l.latitude, l.longitude,
                       COALESCE(ul.custom_radius_meters, l.radius_meters) AS final_radius,
                       CASE WHEN ul.employee_id IS NOT NULL THEN 1 ELSE 0 END AS is_assigned
                FROM locations l
                LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ?
                WHERE l.created_by_admin_id = ?
                ORDER BY is_assigned DESC, l.location_name";
        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("ss", $employee_id, $created_by_admin_id);
            $stmt->execute();
            $result = $stmt->get_result();
            $locations = [];
            while ($row = $result->fetch_assoc()) {
                $locations[] = $row;
            }
            $stmt->close();

            $response['success'] = true;
            $response['message'] = 'Successfully fetched locations.';
            $response['data'] = $locations;
        } else {
            $response['message'] = "Database query error: " . $mysqli->error;
        }
    }

    echo json_encode($response);
    exit;
}

// ===============================================
//        PART X+3: FETCH ATTENDANCE LOGS (AJAX)
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'fetch_attendance_logs') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.', 'data' => []];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];
        $selected_date = $_POST['selected_date'] ?? date('Y-m-d');

        $sql = "SELECT log_datetime, action_type, location_name, status
                FROM checkin_logs
                WHERE employee_id = ? AND DATE(log_datetime) = ?
                ORDER BY log_datetime DESC";

        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("ss", $employee_id, $selected_date);
            $stmt->execute();
            $result = $stmt->get_result();
            $logs = [];
            while ($row = $result->fetch_assoc()) {
                $logs[] = [
                    'time' => date('h:i A', strtotime($row['log_datetime'])),
                    'action' => $row['action_type'],
                    'location' => $row['location_name'] ?? 'N/A',
                    'status' => $row['status'] ?? 'Failed'
                ];
            }
            $stmt->close();
            $response['success'] = true;
            $response['data'] = $logs;
        } else {
            $response['message'] = "Database error: " . $mysqli->error;
        }
    }
    echo json_encode($response);
    exit;
}


// ===============================================
//        PART X+1: EVALUATE CHECK STATUS (AJAX)
// Returns what would be the status for a check action without inserting a row
// Expected POST: action=evaluate_check_status, action_type (Check-In|Check-Out), qr_location_id, qr_secret, user_location_raw
// Response: { success: true, status: 'Good'|'Late'|'Too Far'|'No GPS'|'Invalid QR'|'Absent', distance_m: float, location_name: string }
if (isset($_POST['action']) && $_POST['action'] === 'evaluate_check_status') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated or missing params.', 'data' => null];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];
        $action_type = $_POST['action_type'] ?? '';
        $qr_location_id = (int)($_POST['qr_location_id'] ?? 0);
        $qr_secret = trim($_POST['qr_secret'] ?? '');
        $user_location_raw = trim($_POST['user_location_raw'] ?? '');

        // Basic validation
        if (empty($action_type)) {
            $response['message'] = 'Missing action_type.';
            echo json_encode($response);
            exit;
        }

        $assigned_loc = null;
        $distance_m = null;
        $status = 'Invalid QR';
        $location_name_log = '';

        if ($qr_secret === 'manual') {
            // Manual check: controlled by admin setting 'manual_scan_mode'
            if (!is_manual_scan_allowed()) {
                $response['message'] = 'Manual access is disabled for your account.';
                echo json_encode($response);
                exit;
            }
            // Manual: strict geo enforcement
            $status = 'No GPS';
            $location_name_log = 'Manual Check';
            if ($user_location_raw && strpos($user_location_raw, ',') !== false) {
                list($user_lat, $user_lon) = array_map('floatval', array_map('trim', explode(',', $user_location_raw)));

                // Find closest location
                $created_by_admin_id = '';
                $u_sql = "SELECT created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1";
                if($u_stmt = $mysqli->prepare($u_sql)){
                    $u_stmt->bind_param("s", $employee_id);
                    $u_stmt->execute();
                    $u_res = $u_stmt->get_result();
                    if($u_row = $u_res->fetch_assoc()) $created_by_admin_id = $u_row['created_by_admin_id'];
                    $u_stmt->close();
                }

                $sql_locs = "SELECT l.latitude, l.longitude, l.location_name, COALESCE(ul.custom_radius_meters, l.radius_meters) AS final_radius,
                             CASE WHEN ul.employee_id IS NOT NULL THEN 1 ELSE 0 END AS is_assigned
                             FROM locations l
                             LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ?
                             WHERE l.created_by_admin_id = ?";
                if ($stmt_l = $mysqli->prepare($sql_locs)) {
                    $stmt_l->bind_param("ss", $employee_id, $created_by_admin_id);
                    $stmt_l->execute();
                    $res_l = $stmt_l->get_result();
                    $closest_dist = 9999999;
                    $closest_loc = null;
                    $assigned_nearby = null;
                    while($loc = $res_l->fetch_assoc()){
                        $d = haversine_distance($user_lat, $user_lon, $loc['latitude'], $loc['longitude']);
                        // Prioritize assigned locations if user is within radius
                        if ($loc['is_assigned'] == 1 && $d <= (float)$loc['final_radius']) {
                            if (!$assigned_nearby || $d < $assigned_nearby['dist']) {
                                $assigned_nearby = $loc;
                                $assigned_nearby['dist'] = $d;
                            }
                        }
                        if($d < $closest_dist){
                            $closest_dist = $d;
                            $closest_loc = $loc;
                        }
                    }
                    $stmt_l->close();

                    if ($assigned_nearby) {
                        $closest_loc = $assigned_nearby;
                        $closest_dist = $assigned_nearby['dist'];
                    }

                    if($closest_loc){
                        $distance_m = round($closest_dist, 2);
                        $location_name_log = $closest_loc['location_name'];
                        if($closest_dist <= (float)$closest_loc['final_radius']){
                            $status = 'Good';
                        } else {
                            $status = 'Too Far';
                        }
                    } else {
                        $status = 'Invalid Geo';
                    }
                }
            }
        } else {
            // Normal QR validation
            if ($qr_location_id <= 0) {
                $response['message'] = 'Missing parameters.';
                echo json_encode($response);
                exit;
            }

            // Lookup QR location and radius
            $sql_qr = "SELECT l.latitude, l.longitude, l.qr_secret, l.location_name, COALESCE(ul.custom_radius_meters, l.radius_meters) AS final_radius FROM locations l LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ? WHERE l.id = ?";
            if ($stmt_qr = $mysqli->prepare($sql_qr)) {
                $stmt_qr->bind_param("si", $employee_id, $qr_location_id);
                $stmt_qr->execute();
                $result_qr = $stmt_qr->get_result();
                if ($result_qr->num_rows > 0) {
                    $assigned_loc = $result_qr->fetch_assoc();
                }
                $stmt_qr->close();
            }

            $location_name_log = $assigned_loc['location_name'] ?? '';

            if ($assigned_loc) {
                if ($assigned_loc['qr_secret'] !== $qr_secret) {
                    $status = 'Invalid QR';
                } else {
                    $status = 'Invalid Geo';
                    if ($user_location_raw && strpos($user_location_raw, ',') !== false) {
                        list($user_lat, $user_lon) = array_map('floatval', array_map('trim', explode(',', $user_location_raw)));
                        $distance_m = haversine_distance($user_lat, $user_lon, $assigned_loc['latitude'], $assigned_loc['longitude']);
                        if ($distance_m <= (float)$assigned_loc['final_radius']) {
                            $status = 'Good';
                        } else {
                            $status = 'Too Far';
                        }
                    } else {
                        $status = 'No GPS';
                    }
                }
            }
        }

        // Now check attendance rules to possibly mark Late/Absent when within geo validity
        if ($status === 'Good') {
            $log_datetime = date('Y-m-d H:i:s');
            $current_time = date('H:i:s', strtotime($log_datetime));
            $sql_rules = "SELECT status FROM attendance_rules WHERE employee_id = ? AND type = ? AND start_time <= ? AND end_time >= ?";
            if ($stmt_rules = $mysqli->prepare($sql_rules)) {
                $rule_type = (strtolower($action_type) === 'check-in') ? 'checkin' : 'checkout';
                $stmt_rules->bind_param("ssss", $employee_id, $rule_type, $current_time, $current_time);
                $stmt_rules->execute();
                $result_rules = $stmt_rules->get_result();
                if ($result_rules->num_rows > 0) {
                    $status = ($result_rules->fetch_assoc()['status']) ?? 'Good';
                } else {
                    // If no rule matches, mark as Absent (or decide default)
                    $status = 'Absent';
                }
                $stmt_rules->close();
            }
        }

        $response['success'] = true;
        $response['message'] = 'Evaluated';
        $response['data'] = ['status' => $status, 'distance_m' => $distance_m, 'location_name' => $location_name_log];
    }

    echo json_encode($response);
    exit;
}

// NEW: Save Push Subscription for Web Push
if (isset($_POST['ajax_action']) && $_POST['ajax_action'] === 'save_push_subscription') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.'];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];
        $subscription = json_decode($_POST['subscription'] ?? '{}', true);

        if ($subscription && isset($subscription['endpoint'])) {
            // Create table if not exists (defensive)
            $mysqli->query("CREATE TABLE IF NOT EXISTS push_subscriptions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                endpoint TEXT NOT NULL,
                p256dh VARCHAR(255) NOT NULL,
                auth VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY (endpoint(255))
            )");

            $endpoint = $subscription['endpoint'];
            $p256dh   = $subscription['keys']['p256dh'] ?? '';
            $auth     = $subscription['keys']['auth'] ?? '';

            $sql = "INSERT INTO push_subscriptions (employee_id, endpoint, p256dh, auth)
                    VALUES (?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE employee_id = ?, p256dh = ?, auth = ?";

            if ($stmt = $mysqli->prepare($sql)) {
                $stmt->bind_param("sssssss", $employee_id, $endpoint, $p256dh, $auth, $employee_id, $p256dh, $auth);
                if ($stmt->execute()) {
                    $response = ['success' => true, 'message' => 'Subscription saved.'];
                } else {
                    $response['message'] = 'Database error: ' . $stmt->error;
                }
                $stmt->close();
            }
        } else {
            $response['message'] = 'Invalid subscription data.';
        }
    }
    echo json_encode($response);
    exit;
}


// ===============================================
//        PART X+2: FETCH CLIENT CONFIG (AJAX for Real-time Updates)
// ===============================================
if (isset($_POST['action']) && $_POST['action'] === 'fetch_client_config') {
    header('Content-Type: application/json');
    $response = ['success' => false, 'message' => 'User not authenticated.'];

    if (isset($_SESSION['employee_id'])) {
        $employee_id = $_SESSION['employee_id'];

        // 1. Re-fetch fresh user data
        $sql = "SELECT name, employee_id, custom_data, created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1";
        if ($stmt = $mysqli->prepare($sql)) {
            $stmt->bind_param("s", $employee_id);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($user = $res->fetch_assoc()) {
                $custom_data = json_decode($user['custom_data'] ?? '{}', true) ?: [];

                // 2. Check Manual Scan Permission
                $manual_allowed = is_manual_scan_allowed();

                $response = [
                    'success' => true,
                    'data' => [
                        'user_data' => [
                            'name' => $user['name'],
                            'employee_id' => $user['employee_id']
                        ],
                        'custom_data' => $custom_data,
                        'config' => [
                            'manual_scan_allowed' => $manual_allowed
                        ]
                    ]
                ];
            }
            $stmt->close();
        }
    }
    echo json_encode($response);
    exit;
}


// ===============================================
//        PART 4: STANDARD PAGE LOGIC
// ===============================================

$error_message = '';
$success_message = '';
$is_logged_in = false;
$user_data = [];
$custom_data = [];
$request_counts = ['Pending' => 0, 'Approved' => 0, 'Rejected' => 0];

// --- Logout ---
if (isset($_GET['logout'])) {
    $current_token = $_SESSION['auth_token'] ?? $_COOKIE['auth_token'] ?? null;
    if ($current_token) {
        $stmt_del = $mysqli->prepare("DELETE FROM active_tokens WHERE auth_token = ?");
        if ($stmt_del) {
             $stmt_del->bind_param("s", $current_token);
             $stmt_del->execute();
             $stmt_del->close();
        }
    }
    session_destroy();
    setcookie("auth_token", "", time() - 3600, "/");
    setcookie("scan_user_type", "", time() - 3600, "/");
    header("location: scan.php"); exit;
}

// --- Auto-Login via Token ---
$token = $_SESSION['auth_token'] ?? ($_COOKIE['auth_token'] ?? null);
if ($token) {
    $sql = "SELECT u.employee_id, u.name, u.custom_data
            FROM users u
            JOIN active_tokens at ON u.employee_id = at.employee_id
            WHERE at.auth_token = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $token); $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows == 1) {
            $user_data = $result->fetch_assoc();
            $custom_data = json_decode($user_data['custom_data'] ?? '{}', true);
            $_SESSION['employee_id'] = $user_data['employee_id']; $is_logged_in = true;
            if (!isset($_SESSION['scan_user_type']) && isset($_COOKIE['scan_user_type'])) {
                $_SESSION['scan_user_type'] = $_COOKIE['scan_user_type'];
            }
        } else {
            $error_message = "Token Invalid ឬត្រូវបានលុបចោលដោយ Admin! សូមចូលម្តងទៀត។";
            session_destroy(); setcookie("auth_token", "", time() - 3600, "/");
        }
        $stmt->close();
    }
}

// --- Login via Form ---
if (!$is_logged_in && $_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['login_id'])) {
    $employee_id = trim($_POST['employee_id'] ?? '');
    // NEW: Capture selected user type (Skill / Worker) from login form
    $scan_user_type = strtolower(trim($_POST['scan_user_type'] ?? ''));
    if (!in_array($scan_user_type, ['skill','worker'])) {
        $error_message = "ប្រភេទអ្នកប្រើមិនត្រឹមត្រូវ (Skill / Worker)";
    }
    // Use the creating Admin's global_max_tokens (per-admin setting) instead of super admin
     $sql = "SELECT u.employee_id, u.name, u.custom_data,
                 COALESCE(
                     a.global_max_tokens,
                     (SELECT global_max_tokens FROM users WHERE user_role = 'Admin' AND created_by_admin_id IS NULL LIMIT 1),
                     1
                 ) AS max_tokens_allowed
             FROM users u
             LEFT JOIN users a ON a.employee_id = u.created_by_admin_id AND a.user_role = 'Admin'
             WHERE u.employee_id = ?";
    if ($stmt = $mysqli->prepare($sql)) {
        $stmt->bind_param("s", $employee_id); $stmt->execute();
        $result = $stmt->get_result();
        if ($result->num_rows == 1) {
            $user_db = $result->fetch_assoc();
            $max_tokens = (int)($user_db['max_tokens_allowed'] ?? 1);
            $count_sql = "SELECT COUNT(*) FROM active_tokens WHERE employee_id = ?";
            $stmt_count = $mysqli->prepare($count_sql);
            $stmt_count->bind_param("s", $employee_id); $stmt_count->execute();
            $active_count = $stmt_count->get_result()->fetch_row()[0]; $stmt_count->close();
            if ($active_count >= $max_tokens) {
                $error_message = "កំហុស: លោកអ្នកបានចូលប្រើលើសចំនួនកំណត់ ({$max_tokens})។";
            } else {
                // Department validation by selected type
                $custom_data_login = json_decode($user_db['custom_data'] ?? '{}', true) ?: [];
                $department_value = $custom_data_login['department'] ?? $custom_data_login['workplace'] ?? $custom_data_login['workplace_name'] ?? $custom_data_login['នាយកដ្ឋាន'] ?? '';
                // Strict validation: if department contains 'worker' or 'កម្មករ', must select 'worker'; if 'skill' or 'ជំនាញ', must select 'skill'
                $dept_lower = mb_strtolower($department_value, 'UTF-8');
                $is_worker_dept = (mb_strpos($dept_lower, 'worker', 0, 'UTF-8') !== false) || (mb_strpos($dept_lower, 'កម្មករ', 0, 'UTF-8') !== false);
                $is_skill_dept = (mb_strpos($dept_lower, 'skill', 0, 'UTF-8') !== false) || (mb_strpos($dept_lower, 'ជំនាញ', 0, 'UTF-8') !== false);
                if ($is_worker_dept && $scan_user_type !== 'worker') {
                    $error_message = "ប្រភេទអ្នកប្រើមិនត្រឹមត្រូវសម្រាប់នាយកដ្ឋាននេះ។ សូមជ្រើសរើស 'កម្មករ'។";
                    // Send Telegram notification for wrong user type selection
                    $telegram_msg = "🚨 Wrong User Type Selected\n\nEmployee ID: {$employee_id}\nDepartment: {$department_value}\nSelected Type: {$scan_user_type}\nRequired: worker\nTime: " . date('Y-m-d H:i:s');
                    sendTelegramMessage($mysqli, $telegram_msg, 'generic');
                } elseif ($is_skill_dept && $scan_user_type !== 'skill') {
                    $error_message = "ប្រភេទអ្នកប្រើមិនត្រឹមត្រូវសម្រាប់នាយកដ្ឋាននេះ។ សូមជ្រើសរើស 'ជំនាញ'។";
                    // Send Telegram notification for wrong user type selection
                    $telegram_msg = "🚨 Wrong User Type Selected\n\nEmployee ID: {$employee_id}\nDepartment: {$department_value}\nSelected Type: {$scan_user_type}\nRequired: skill\nTime: " . date('Y-m-d H:i:s');
                    sendTelegramMessage($mysqli, $telegram_msg, 'generic');
                } else {
                    list($dept_ok, $normalized_dept, $allowed_list_display) = department_allowed_for_type($scan_user_type, $department_value);
                    if (!$dept_ok) {
                        $error_message = "នាយកដ្ឋានរបស់អ្នក (" . htmlspecialchars($normalized_dept) . ") មិនមានក្នុងបញ្ជីអនុញ្ញាតសម្រាប់ប្រភេទនេះទេ។";
                    } elseif (empty($error_message)) {
                        $new_token = bin2hex(random_bytes(32));
                        $insert_token_sql = "INSERT INTO active_tokens (employee_id, auth_token) VALUES (?, ?)";
                        if ($insert_stmt = $mysqli->prepare($insert_token_sql)) {
                            $insert_stmt->bind_param("ss", $employee_id, $new_token); $insert_stmt->execute(); $insert_stmt->close();
                            $_SESSION['employee_id'] = $employee_id; $_SESSION['auth_token'] = $new_token; $_SESSION['scan_user_type'] = $scan_user_type;
                            setcookie("auth_token", $new_token, time() + (86400 * 365), "/");
                            setcookie("scan_user_type", $scan_user_type, time() + (86400 * 365), "/");
                            $user_data = $user_db;
                            $custom_data = json_decode($user_db['custom_data'] ?? '{}', true);
                            $is_logged_in = true;
                            $success_message = "Login ជោគជ័យ! សូមស្វាគមន៍ " . $user_data['name'];
                        }
                    }
                }
            }
        } else {
            $error_message = "ID មិនត្រឹមត្រូវ ឬមិនមានក្នុងប្រព័ន្ធ!";
        }
        $stmt->close();
    }
}


// --- Process Check-In/Out ---
if ($is_logged_in && $_SERVER["REQUEST_METHOD"] == "POST" && isset($_POST['action']) && !in_array($_POST['action'], ['upload_signature', 'submit_request', 'fetch_requests', 'fetch_signature_history', 'fetch_last_action', 'fetch_request_counts'])) {
    $action = $_POST['action']; $employee_id = $_SESSION['employee_id']; $name = $user_data['name'];
    // Defensive: prefer explicit POST values but fall back to server-side $custom_data when POST missing/placeholder
    $posted_workplace = isset($_POST['workplace']) ? trim($_POST['workplace']) : '';
    $posted_branch = isset($_POST['branch']) ? trim($_POST['branch']) : '';

    // [កូដដែលបានកែសម្រួល] ប្រើ Coalescing Operator ដើម្បីស្វែងរក Key ជាច្រើន (ភាសាអង់គ្លេស និងខ្មែរ)
    $workplace = ($posted_workplace !== '' && $posted_workplace !== 'N/A') ? $posted_workplace : ($custom_data['workplace'] ?? $custom_data['workplace_name'] ?? $custom_data['department'] ?? $custom_data['នាយកដ្ឋាន'] ?? '');
    $branch = ($posted_branch !== '' && $posted_branch !== 'N/A') ? $posted_branch : ($custom_data['branch'] ?? $custom_data['branch_name'] ?? $custom_data['សាខា'] ?? '');

    $area = trim($_POST['area'] ?? ($custom_data['area'] ?? ''));
    $qr_location_id = (int)($_POST['qr_location_id'] ?? 0);
    $qr_secret = trim($_POST['qr_secret'] ?? ''); $user_location_raw = trim($_POST['user_location_raw'] ?? '');
    $log_datetime = (!empty($_POST['log_datetime'])) ? trim($_POST['log_datetime']) : date('Y-m-d H:i:s');
    $current_time = date('H:i:s', strtotime($log_datetime));
    $late_reason = trim($_POST['late_reason'] ?? ''); $log_status = 'Good';
    $location_validity = 'Invalid QR'; $min_distance_m = 0.0;

    $assigned_loc = null;
    $location_name_log = 'Unknown/Invalid Location';
    if ($qr_secret === 'manual') {
        // Manual scan: controlled by admin setting 'manual_scan_mode'
        if (!is_manual_scan_allowed()) {
            $error_message = "កំហុស៖ វត្តមានដោយដៃមិនត្រូវបានអនុញ្ញាតសម្រាប់គណនីរបស់អ្នកទេ។";
            $location_validity = 'Invalid';
        } else {
            // Manual attendance: strict geo enforcement
            $location_validity = 'Invalid Geo';
        $location_name_log = 'Manual Check';
        // Use distance from form field for manual attendance
        $min_distance_m = floatval($_POST['manual_distance'] ?? 0);
        if (strpos($user_location_raw, ',') !== false && $user_location_raw !== '0,0') {
            list($user_lat, $user_lon) = array_map('floatval', array_map('trim', explode(',', $user_location_raw)));

            // Find closest location
            $created_by_admin_id = '';
            $u_sql = "SELECT created_by_admin_id FROM users WHERE employee_id = ? LIMIT 1";
            if($u_stmt = $mysqli->prepare($u_sql)){
                $u_stmt->bind_param("s", $employee_id);
                $u_stmt->execute();
                $u_res = $u_stmt->get_result();
                if($u_row = $u_res->fetch_assoc()) $created_by_admin_id = $u_row['created_by_admin_id'];
                $u_stmt->close();
            }

            $sql_locs = "SELECT l.latitude, l.longitude, l.location_name, COALESCE(ul.custom_radius_meters, l.radius_meters) AS final_radius,
                         CASE WHEN ul.employee_id IS NOT NULL THEN 1 ELSE 0 END AS is_assigned
                         FROM locations l
                         LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ?
                         WHERE l.created_by_admin_id = ?";
            if ($stmt_l = $mysqli->prepare($sql_locs)) {
                $stmt_l->bind_param("ss", $employee_id, $created_by_admin_id);
                $stmt_l->execute();
                $res_l = $stmt_l->get_result();
                $closest_dist = 9999999;
                $closest_loc = null;
                $assigned_nearby = null;
                while($loc = $res_l->fetch_assoc()){
                    $d = haversine_distance($user_lat, $user_lon, $loc['latitude'], $loc['longitude']);
                    // Prioritize assigned locations if user is within radius
                    if ($loc['is_assigned'] == 1 && $d <= (float)$loc['final_radius']) {
                        if (!$assigned_nearby || $d < $assigned_nearby['dist']) {
                            $assigned_nearby = $loc;
                            $assigned_nearby['dist'] = $d;
                        }
                    }
                    if($d < $closest_dist){
                        $closest_dist = $d;
                        $closest_loc = $loc;
                    }
                }
                $stmt_l->close();

                if ($assigned_nearby) {
                    $closest_loc = $assigned_nearby;
                    $closest_dist = $assigned_nearby['dist'];
                }

                if($closest_loc){
                    $min_distance_m = round($closest_dist, 2);
                    $location_name_log = $closest_loc['location_name'];
                    // Use TOLERANCE buffer (default 100m)
                    $allowed_radius = (float)$closest_loc['final_radius'] + (defined('TOLERANCE') ? TOLERANCE : 100);
                    if($closest_dist <= $allowed_radius){
                        $location_validity = 'Valid Geo';
                    } else {
                        // User is far, but we allow submission with a warning flag
                        $location_validity = 'Valid Geo'; // Allow it to pass further down
                        $is_outside_range = true;
                        $outside_msg = "អ្នកនៅឆ្ងាយពីទីតាំង ({$min_distance_m}m / Max: {$closest_loc['final_radius']}m)";
                    }
                } else {
                    $error_message = "កំហុស៖ មិនមានទីតាំងត្រូវបានកំណត់សម្រាប់លោកអ្នកទេ។";
                    $location_validity = 'Invalid Geo';
                }
            }
        } else {
            $error_message = "កំហុស GPS: មិនអាចទាញយកទីតាំងបច្ចុប្បន្នបានទេ។";
            $location_validity = 'No GPS';
        }
        }
    } else {
        // Normal QR-based attendance
        $sql_qr = "SELECT l.latitude, l.longitude, l.qr_secret, l.location_name, COALESCE(ul.custom_radius_meters, l.radius_meters) AS final_radius FROM locations l LEFT JOIN user_locations ul ON l.id = ul.location_id AND ul.employee_id = ? WHERE l.id = ?";
        if ($stmt_qr = $mysqli->prepare($sql_qr)) {
            $stmt_qr->bind_param("si", $employee_id, $qr_location_id); $stmt_qr->execute();
            $result_qr = $stmt_qr->get_result();
        if ($result_qr->num_rows > 0) {
            $assigned_loc = $result_qr->fetch_assoc();
            $location_name_log = $assigned_loc['location_name'];
            if ($assigned_loc['qr_secret'] === $qr_secret) $location_validity = 'QR Valid'; else $error_message = "កំហុស QR: Secret Key មិនត្រឹមត្រូវ! (QR Hacked)";
        } else { $error_message = "កំហុស QR: QR ID នេះមិនមាន ឬមិនត្រូវបានអនុញ្ញាតសម្រាប់លោកអ្នកទេ។"; }
            $stmt_qr->close();
        }

        if ($location_validity === 'QR Valid' && strpos($user_location_raw, ',') !== false) {
            list($user_lat, $user_lon) = array_map('floatval', array_map('trim', explode(',', $user_location_raw)));
            $distance_m = haversine_distance($user_lat, $user_lon, $assigned_loc['latitude'], $assigned_loc['longitude']);
            $min_distance_m = round($distance_m, 2);
            $allowed_radius = (float)$assigned_loc['final_radius'] + (defined('TOLERANCE') ? TOLERANCE : 100);
            if ($distance_m <= $allowed_radius) {
                $location_validity = 'Valid Geo';
            } else {
                // Soft Geofencing: Allow the submission but note it was outside
                $location_validity = 'Valid Geo';
                $is_outside_range = true;
                $outside_msg = "អ្នកនៅឆ្ងាយពីទីតាំង ({$min_distance_m}m / Max: {$assigned_loc['final_radius']}m)";
            }
        } elseif ($location_validity === 'QR Valid') { $error_message = "កំហុស GPS: មិនអាចទាញយកទីតាំងបច្ចុប្បន្នបានទេ។"; $location_validity = 'No GPS'; }
    }

    $sql_rules = "SELECT status, start_time FROM attendance_rules WHERE employee_id = ? AND type = ? AND start_time <= ? AND end_time >= ? ORDER BY start_time DESC";
    $matched_rule_start = '';
    if ($stmt_rules = $mysqli->prepare($sql_rules)) {
        $rule_type = (strtolower($action) === 'check-in') ? 'checkin' : 'checkout';
        $stmt_rules->bind_param("ssss", $employee_id, $rule_type, $current_time, $current_time);
        $stmt_rules->execute();
        $result_rules = $stmt_rules->get_result();
        if ($row_rule = $result_rules->fetch_assoc()) {
            $log_status = $row_rule['status'] ?? 'Good';
            $matched_rule_start = $row_rule['start_time'] ?? '';
        } else { $log_status = 'Absent'; $error_message = $error_message ?: "កំហុសម៉ោង៖ ម៉ោង {$current_time} មិនស្ថិតនៅក្នុងចន្លោះ Check-In/Out ដែលបានកំណត់ទេ។"; }
        $stmt_rules->close();
    }

    $status_for_db = $log_status;
    // Allow Check-Out Late -> Good upgrade when user provided a late_reason and client indicates override
    if (strcasecmp($action, 'Check-Out') === 0 && $log_status === 'Late') {
        $override = trim($_POST['status_override'] ?? '');
        if ($override !== '' && strcasecmp($override, 'Good') === 0 && $late_reason !== '') {
            $status_for_db = 'Good';
        }
    }
    $location_log = $user_location_raw;
    if ($qr_secret === 'manual') {
        $location_name_log = trim($_POST['manual_location_name'] ?? 'Manual Check');
    } else {
        $location_name_log = $assigned_loc['location_name'] ?? 'Manual Check';
    }

    if ($location_validity !== 'Valid Geo') {
        if ($location_validity === 'Too Far') {
            // This case should now be rare due to soft geofencing above, but we keep it for fallback
            $error_message = "កំហុស Geo: អ្នកនៅឆ្ងាយពីទីតាំងដែលបានស្កេន ({$min_distance_m} m / Max: {$assigned_loc['final_radius']} m)។";
        } elseif ($location_validity === 'Invalid QR') {
            // Error message already set
        } elseif ($location_validity === 'No GPS') {
            $error_message = "កំហុស GPS: មិនអាចទាញយកទីតាំងបច្ចុប្បន្នបានទេ។";
        }
    } elseif ($log_status === 'Absent') {
        $error_message = $error_message ?: "កំហុសម៉ោង៖ ម៉ោង {$current_time} មិនស្ថិតនៅក្នុងចន្លោះ Check-In/Out ដែលបានកំណត់ទេ។";
    } else {
           // [កូដដែលបានកែសម្រួល] បម្លែងข้อมูล $custom_data ទៅជា JSON string
    $custom_fields_json = json_encode($custom_data, JSON_UNESCAPED_UNICODE);

    $status_value_sql = "'" . $mysqli->real_escape_string($status_for_db) . "'";

    // CALCULATE LATE MINUTES (Moved here to save to DB)
    $late_minutes_val = 0;
    $late_minutes_display = '';
    if (strcasecmp($status_for_db, 'Late') === 0) {
        $type = (strcasecmp($action, 'Check-In') === 0) ? 'checkin' : 'checkout';
        $current_hms = date('H:i:s', strtotime($log_datetime));

        $p_time = $matched_rule_start;

        // If for some reason we don't have a matched rule start (shouldn't happen if status is Late),
        // fallback to the old logic of finding the latest Good slot or the first slot.
        if ($p_time === '') {
            // 1) Primary rule: take the latest end_time of a Good slot that ends <= current time
            if ($stmt_pv = $mysqli->prepare("SELECT end_time FROM attendance_rules WHERE employee_id = ? AND type = ? AND status = 'Good' AND end_time <= ? ORDER BY end_time DESC LIMIT 1")) {
                $stmt_pv->bind_param('sss', $employee_id, $type, $current_hms);
                if ($stmt_pv->execute()) {
                    $res_pv = $stmt_pv->get_result();
                    if ($row_pv = $res_pv->fetch_assoc()) {
                        $p_time = $row_pv['end_time'];
                    }
                }
                $stmt_pv->close();
            }

            // 2) Fallback: first start_time for this type
            if ($p_time === '' && $stmt_ec = $mysqli->prepare("SELECT start_time FROM attendance_rules WHERE employee_id = ? AND type = ? ORDER BY start_time ASC LIMIT 1")) {
                $stmt_ec->bind_param('ss', $employee_id, $type);
                if ($stmt_ec->execute()) {
                    $res_ec = $stmt_ec->get_result();
                    if ($row_ec = $res_ec->fetch_assoc()) {
                        $p_time = $row_ec['start_time'];
                    }
                }
                $stmt_ec->close();
            }
        }

        if ($p_time !== '') {
            $expected_dt = date('Y-m-d', strtotime($log_datetime)) . ' ' . $p_time;
            $diff_seconds = strtotime($log_datetime) - strtotime($expected_dt);
            if ($diff_seconds > 0) {
                // FIX: Use ceil for accurate minutes (e.g., 3m 25s -> 4m)
                $late_minutes_val = (int)ceil($diff_seconds / 60);
                if ($late_minutes_val >= 60) {
                    $h = intdiv($late_minutes_val, 60);
                    $m = $late_minutes_val % 60;
                    $late_minutes_display = ($m === 0) ? ($h . ' ម៉ោង') : ($h . ' ម៉ោង ' . $m . ' នាទី');
                } else {
                    $late_minutes_display = $late_minutes_val . ' នាទី';
                }
                $status_for_db_with_minutes = 'Late ( ' . $late_minutes_display . ' )';
            }
        }
    }

    if (isset($is_outside_range) && $is_outside_range) {
        $status_for_db = (strpos($status_for_db, ' ( Outside )') === false) ? $status_for_db . ' ( Outside )' : $status_for_db;
        if (isset($status_for_db_with_minutes)) {
             $status_for_db_with_minutes .= ' ( Outside )';
        }
    }


    // [កូដដែលបានកែសម្រួល] បន្ថែម `custom_fields_data` និង `late_minutes` ទៅក្នុង INSERT statement
    $insert_sql = "INSERT INTO checkin_logs (employee_id, name, action_type, workplace, branch, log_datetime, late_reason, area, location_data, status, distance_m, location_name, custom_fields_data, late_minutes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, {$status_value_sql}, ?, ?, ?, ?)";

    if ($stmt_insert = $mysqli->prepare($insert_sql)) {
        // Bind types: 9 strings, 1 double, 1 string, 1 string, 1 int
        $stmt_insert->bind_param("sssssssssdssi", $employee_id, $name, $action, $workplace, $branch, $log_datetime, $late_reason, $area, $location_log, $min_distance_m, $location_name_log, $custom_fields_json, $late_minutes_val);

        if ($stmt_insert->execute()) {
                $status_label_success = isset($status_for_db_with_minutes) ? $status_for_db_with_minutes : $status_for_db;
                $success_message = "{$action} បានសម្រេច! (ស្ថានភាព: {$status_label_success})";
                if (isset($is_outside_range) && $is_outside_range) {
                    $success_message .= " [បញ្ជាក់: ទីតាំងលើស Radius ({$min_distance_m}m)]";
                }

                // Dynamic status icon (Good / Late) from admin settings, fallback to defaults
                $icon_good = get_setting('status_icon_good', '🔵');
                $icon_late = get_setting('status_icon_late', '🔴');
                $status_icon = ($status_for_db === 'Good') ? $icon_good : $icon_late;
                $map_url = '';
                $map_link_markup = '';
                if (!empty($user_location_raw) && strpos($user_location_raw, ',') !== false) {
                    list($lat, $lon) = explode(',', $user_location_raw);
                    $map_url = "https://maps.google.com/?q=" . urlencode(trim($lat)) . "," . urlencode(trim($lon));
                    $map_link_markup = '<a href="' . htmlspecialchars($map_url, ENT_QUOTES, 'UTF-8') . '">មើលផែនទី</a>';
                }
                // Ensure formatted time is always defined for attendance messages
                $time_format = get_setting('telegram_time_format', 'Y-m-d H:i:s');
                $formatted_time = date($time_format);
                $tplA = get_setting('telegram_tpl_attendance', '<b>[ATTENDANCE]</b>\n<b>ឈ្មោះ:</b> {{name}}\n<b>ID:</b> {{employee_id}}\n<b>សកម្មភាព:</b> {{action}} ({{status_icon}} {{status}})\n<b>ម៉ោង:</b> {{time}}\n<b>ទីតាំង:</b> {{location_name}}\n<b>ចំងាយ:</b> {{distance_m}} ({{distance_status}})\n{{late_reason_section}}\n{{map_url}}');
                // Format distance display
                $distance_display = $min_distance_m . ' ';

                // Determine distance status
                $distance_status = 'Manual';
                if ($assigned_loc && isset($assigned_loc['final_radius'])) {
                    $allowed_radius = (float)$assigned_loc['final_radius'];
                    if ($min_distance_m <= $allowed_radius) {
                        $distance_status = 'ស្ថិតក្នុងរង្វង់ (' . $allowed_radius . ' )';
                    } else {
                        $distance_status = 'អត់ស្ថិតក្នុងរង្វង់ (' . $allowed_radius . ' )';
                    }
                }

                $replA = [
                    '{{name}}' => htmlspecialchars($name),
                    '{{employee_id}}' => htmlspecialchars($employee_id),
                    '{{action}}' => htmlspecialchars($action),
                    // If we calculated minutes, adjust status label
                    '{{status}}' => htmlspecialchars(isset($status_for_db_with_minutes) ? $status_for_db_with_minutes : $status_for_db),
                    '{{status_icon}}' => $status_icon,
                        '{{time}}' => format_time_for_placeholder($time_format),
                    '{{location_name}}' => htmlspecialchars($location_name_log),
                    '{{distance_m}}' => $distance_display,
                    '{{distance_status}}' => $distance_status,
                    // Raw reason without label so admins can put their own label in template
                    '{{late_reason}}' => $late_reason ? htmlspecialchars($late_reason) : '',
                    // Convenience section that auto-hides if empty (with default Khmer label)
                    '{{late_reason_section}}' => $late_reason ? ('<b>Reason:</b> ' . htmlspecialchars($late_reason)) : '',
                    '{{map_url}}' => $map_url ? ('' . $map_link_markup) : ''
                ];
                // Provide extra placeholder specifically for late minutes if template wants to use it
                $replA['{{late_minutes}}'] = $late_minutes_display ? htmlspecialchars($late_minutes_display) : '';
                // Dynamic employee custom fields placeholders: {{field_<field_key>}}
                if (isset($custom_data) && is_array($custom_data)) {
                    foreach ($custom_data as $cKey => $cVal) {
                        if (!is_scalar($cVal)) continue;
                        // Normalize common cases where custom_data keys may already include 'field_'
                        $norm = (strpos($cKey, 'field_') === 0) ? substr($cKey, 6) : $cKey;
                        $ph = '{{field_' . $norm . '}}';
                        if (strpos($tplA, $ph) !== false) {
                            $replA[$ph] = htmlspecialchars((string)$cVal);
                        }
                        // Also allow direct raw-key placeholders if present
                        $phRaw = '{{' . $cKey . '}}';
                        if (strpos($tplA, $phRaw) !== false) {
                            $replA[$phRaw] = htmlspecialchars((string)$cVal);
                        }
                    }
                }
                // Backward compatibility: if template lacks {{status_icon}}, prepend icon to {{status}}
                if (strpos($tplA, '{{status_icon}}') === false && !empty($status_icon)) {
                    $replA['{{status}}'] = trim($status_icon . ' ' . ($replA['{{status}}'] ?? ''));
                }
                $telegram_msg = render_template_strip_empty_lines($tplA, $replA);
                // Force send attendance regardless of notify_attendance flag (always deliver)
                sendTelegramMessage($mysqli, $telegram_msg, 'attendance_force');
                $admin_id_to_notify = get_current_admin_id($mysqli);
                sendWebPushNotification($mysqli, $admin_id_to_notify, "Attendance: {$action}", strip_tags(str_replace('\n', "\n", $telegram_msg)));
                // Also notify the employee themselves
                sendWebPushNotification($mysqli, $employee_id, "វត្តមាន: {$action}", "អ្នកបាន {$action} ដោយជោគជ័យ។");

            } else { $error_message = "Error: មិនអាចបញ្ចូលទិន្នន័យបានទេ " . $stmt_insert->error; }
            $stmt_insert->close();
        } else { $error_message = "កំហុស Prepared Statement របស់ Check-In: " . $mysqli->error; }
    }
}


// ===============================================
//        PART 5: FETCH REQUEST COUNTS
// ===============================================
if ($is_logged_in) {
    $employee_id = $_SESSION['employee_id'];
    $sql_counts = "SELECT request_status, COUNT(*) as count FROM requests_logs WHERE employee_id = ? GROUP BY request_status";
    if ($stmt_counts = $mysqli->prepare($sql_counts)) {
        $stmt_counts->bind_param("s", $employee_id);
        $stmt_counts->execute();
        $result_counts = $stmt_counts->get_result();
        while ($row = $result_counts->fetch_assoc()) {
            if (isset($request_counts[$row['request_status']])) {
                $request_counts[$row['request_status']] = (int)$row['count'];
            }
        }
        $stmt_counts->close();
    }
}
?>

<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <meta name="apple-mobile-web-app-capable" content="yes">
    <meta name="mobile-web-app-capable" content="yes">
    <meta name="apple-mobile-web-app-status-bar-style" content="default">
    <meta name="apple-mobile-web-app-title" content="Attendance_App">
    <link rel="apple-touch-icon" href="https://cdn-icons-png.flaticon.com/512/11693/11693253.png">

    <!-- Splash Screen for iOS devices to prevent black screen on launch -->
    <!-- Using a basic link as a fallback for all iOS devices -->
    <link rel="apple-touch-startup-image" href="https://cdn-icons-png.flaticon.com/512/11693/11693253.png">

    <link rel="manifest" href="manifest.json">

    <meta name="theme-color" content="#007aff">
    <title>ប្រព័ន្ធគ្រប់គ្រងបុគ្គលិក</title>

    <!-- CRITICAL: Immediate Theme & Background Initialization -->
    <script>
        (function() {
            const savedTheme = localStorage.getItem('appTheme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
            document.documentElement.setAttribute('data-theme', savedTheme);
            const bgColor = (savedTheme === 'dark') ? '#000000' : '#f2f2f7';
            document.head.insertAdjacentHTML('beforeend', `<style>html, body { background: ${bgColor} !important; height: 100%; margin: 0; }</style>`);
        })();
    </script>

    <link rel="preload" href="assets/css/fontawesome/all.min.css" as="style">
    <link rel="preload" href="assets/css/webfonts/fa-solid-900.woff2" as="font" type="font/woff2" crossorigin>
    <link rel="preload" href="assets/js/html5-qrcode.min.js" as="script">

    <script src="assets/js/html5-qrcode.min.js"></script>

    <link href="https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="assets/css/fontawesome/all.min.css" />
    <style>
        /* Local Momo Trust Display (Latin only) */
        @font-face {
            font-family: 'Momo Trust Display';
            src: url('assets/fonts/MomoTrustDisplay-Regular.woff2') format('woff2'),
                 url('assets/fonts/MomoTrustDisplay-Regular.woff') format('woff'),
                 url('assets/fonts/MomoTrustDisplay-Regular.ttf') format('truetype');
            font-weight: 400;
            font-style: normal;
            font-display: swap;
            /* Latin + common symbols only, Khmer will fall back to Kantumruy */
            unicode-range: U+0000-00FF, U+0131, U+0152-0153, U+02BB-02BC, U+02C6, U+02DA, U+02DC,
                           U+2000-206F, U+2074, U+20AC, U+2122, U+2191, U+2193, U+2212, U+2215, U+FEFF, U+FFFD;
        }
        /* ... (Existing CSS) ... */
        :root {
            --primary-color: #007aff; --primary-color-dark: #005ecb; --primary-color-light: #66b5ff;
            --secondary-color: #f2f2f7; --success-color: #34c759; --error-color: #ff3b30;
            --warning-color: #ff9500; --background-color: #f2f2f7; --surface-color: #ffffffff;
            --text-primary: #1c1c1e; --text-secondary: #8a8a8e; --text-on-primary: #ffffff;
            --border-radius-s: 12px; --border-radius-m: 20px; --border-radius-l: 28px;
            --shadow-sm: 0 2px 8px rgba(0, 0, 0, 0.06); --shadow-md: 0 4px 15px rgba(0, 0, 0, 0.1);
            --shadow-lg: 0 8px 32px rgba(0, 0, 0, 0.12); --shadow-xl: 0 20px 40px rgba(0, 0, 0, 0.15);
            --blur-sm: blur(8px); --blur-md: blur(16px);
            --header-height: 86px; --footer-height: 76px;
            --glass-bg: rgba(255, 255, 255, 0.8); --glass-border: rgba(255, 255, 255, 0.2);
        }

        /***************************************/
        /* START: DARK THEME STYLES */
        /***************************************/
        html[data-theme='dark'] {
            --primary-color: #0a84ff; --primary-color-dark: #0060d1; --primary-color-light: #52a8ff;
            --secondary-color: #1c1c1e; --success-color: #30d158; --error-color: #ff453a;
            --warning-color: #ff9f0a; --background-color: #000000; --surface-color: #1c1c1e;
            --text-primary: #ffffff; --text-secondary: #8e8e93; --text-on-primary: #ffffff;
            --glass-bg: rgba(28, 28, 30, 0.8); --glass-border: rgba(142, 142, 147, 0.2);
        }
        html[data-theme='dark'] .menu-card,
        html[data-theme='dark'] .form-section,
        html[data-theme='dark'] .request-status-card {
            border: 1px solid #3a3a3c;
        }
        html[data-theme='dark'] .mobile-input {
            background-color: #2c2c2e;
            border-color: #3a3a3c;
            color: var(--text-primary);
        }
        html[data-theme='dark'] .mobile-input:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 3px rgba(10, 132, 255, 0.3);
        }
        html[data-theme='dark'] select.mobile-input {
             background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3e%3cpath fill='none' stroke='%238e8e93' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M2 5l6 6 6-6'/%3e%3c/svg%3e");
        }
        html[data-theme='dark'] .logout-btn {
            background: #2c2c2e;
            color: var(--primary-color);
        }
        html[data-theme='dark'] .logout-btn:active {
            background-color: #3a3a3c;
        }
        html[data-theme='dark'] .history-item {
             border: 1px solid #3a3a3c;
        }



        /* PREMIUM MENU CARDS */
        .card-menu {
            display: grid;
            grid-template-columns: 1fr;
            gap: 16px;
            margin-top: 10px;
        }

        .menu-card {
            display: flex;
            align-items: center;
            padding: 20px;
            background: #ffffff;
            border-radius: 22px;
            border: 1px solid rgba(0,0,0,0.04);
            box-shadow: 0 8px 16px rgba(0,0,0,0.03);
            transition: all 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
            cursor: pointer;
            position: relative;
            overflow: hidden;
        }

        .menu-card:active {
            transform: scale(0.96);
            background: #fdfdfd;
            box-shadow: 0 4px 12px rgba(0,0,0,0.05);
        }

        .menu-card::after {
            content: '';
            position: absolute;
            right: 20px;
            font-family: "Font Awesome 6 Free";
            font-weight: 900;
            content: "\f054";
            font-size: 0.8em;
            color: #ccc;
            opacity: 0.5;
        }

        .card-icon {
            width: 54px;
            height: 54px;
            background: linear-gradient(135deg, var(--primary-color), var(--primary-color-dark));
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-size: 1.4em;
            box-shadow: 0 6px 14px rgba(0, 122, 255, 0.2);
            flex-shrink: 0;
        }

        .card-text {
            margin-left: 16px;
        }

        .card-text h3 {
            margin: 0;
            font-size: 1.05rem;
            font-weight: 700;
            color: var(--text-primary);
            letter-spacing: -0.3px;
        }

        .card-text p {
            margin: 2px 0 0 0;
            font-size: 0.85rem;
            color: var(--text-secondary);
            opacity: 0.8;
        }

        /* DARK MODE ADJUSTMENTS */
        html[data-theme='dark'] .menu-card {
            background: #1c1c1e;
            border-color: rgba(255,255,255,0.08);
            box-shadow: 0 8px 16px rgba(0,0,0,0.2);
        }



        html[data-theme='dark'] .card-text h3 { color: #ffffff; }
        html[data-theme='dark'] .card-text p { color: #8e8e93; }
        html[data-theme='dark'] #request-logs-table th,
        html[data-theme='dark'] #request-logs-table td {
             border-bottom: 1px solid #3a3a3c;
        }
        html[data-theme='dark'] #request-logs-table th {
             background-color: #2c2c2e;
        }
        html[data-theme='dark'] .theme-switcher {
            border-color: #3a3a3c;
        }
        html[data-theme='dark'] .back-button {
             color: var(--primary-color);
        }
        /***************************************/
        /* END: DARK THEME STYLES */
        /***************************************/

    * { -webkit-tap-highlight-color: transparent; box-sizing: border-box; }
    /* Apply Momo Trust Display for English (Latin). Khmer falls back to Kantumruy Pro. */
    body {
        font-family: 'Momo Trust Display', 'Kantumruy Pro', -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif;
        margin: 0; padding: 0;
        background: linear-gradient(135deg, var(--background-color) 0%, rgba(242, 242, 247, 0.8) 100%);
        color: var(--text-primary);
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
        box-sizing: border-box;
        transition: background-color 0.3s ease, color 0.3s ease;
        min-height: 100vh;
        background-attachment: fixed;
    }
    /* Do NOT apply Momo font in inputs or buttons */
    input, textarea, select, button, .mobile-input, .mobile-button, .btn {
        font-family: 'Kantumruy Pro', -apple-system, system-ui, Segoe UI, Roboto, Arial, sans-serif !important;
    }
    .mobile-body {
        max-width: 500px;
        margin: 0 auto;
        min-height: 100vh;
        background: var(--glass-bg);
        backdrop-filter: var(--blur-sm);
        -webkit-backdrop-filter: var(--blur-sm);
        border: 1px solid var(--glass-border);
        box-shadow: var(--shadow-xl);
        position: relative;
        border-radius: 0 0 var(--border-radius-l) var(--border-radius-l);
        overflow: hidden;
    }
        /* លុប app-container ចោល ឬទុកវាឱ្យដូចដើម។ ខ្ញុំនឹងទុកវាចោលដើម្បីភាពងាយស្រួល */
.app-container {
    /* លុប flex-grow: 1; display: flex; flex-direction: column; ចេញពី app-container */
    min-height: calc(100vh - 0px); /* កែសម្រួលតាមតម្រូវការ */
}
    .app-header {
        background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-color-dark) 50%, var(--primary-color) 100%);
        color: var(--text-primary);
        padding: 0;
        text-align: center;
        position: fixed;
        top: 0;
        left: 50%;
        transform: translateX(-50%);
        width: 100%;
        max-width: 500px;
        z-index: 1000;
        backdrop-filter: var(--blur-md);
        -webkit-backdrop-filter: var(--blur-md);
        border-bottom: 1px solid rgba(255, 255, 255, 0.2);
        box-shadow: 0 4px 20px rgba(0, 122, 255, 0.15);
        overflow: hidden;
    }
    .app-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(45deg, rgba(255, 255, 255, 0.1) 0%, transparent 50%, rgba(255, 255, 255, 0.05) 100%);
        pointer-events: none;
    }
    .header-content {
        display: flex;
        justify-content: space-between;
        align-items: center;
        max-width: 100%;
        padding: 16px 24px;
        min-height: 56px;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: var(--blur-sm);
        -webkit-backdrop-filter: var(--blur-sm);
        border-radius: 0 0 var(--border-radius-m) var(--border-radius-m);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.1);
    }
    .header-title {
        margin: 0;
        font-size: 1.25em;
        font-weight: 700;
        color: white;
        text-shadow: 0 2px 4px rgba(0, 0, 0, 0.2);
        letter-spacing: -0.02em;
    }
        .logout-btn { background: var(--secondary-color); color: var(--primary-color); padding: 8px 16px; border: none; border-radius: var(--border-radius-s); text-decoration: none; font-size: 0.9em; font-weight: 500; transition: background-color 0.2s ease, transform 0.1s ease; }
        .logout-btn:active { background-color: #e5e5ea; transform: scale(0.96); }
        #login-view { display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; height: 100%; padding: 20px; flex-grow: 1; }
    .login-icon { font-size: 4em; color: var(--primary-color); margin-bottom: 24px; background: linear-gradient(135deg, var(--primary-color-light), var(--primary-color)); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent; }
    .app-main {
        padding: 24px 20px;
        padding-top: calc(var(--header-height) + 16px);
        padding-bottom: calc(var(--footer-height) + 32px);
        flex-grow: 1;
        margin: 0 auto;
        max-width: 500px;
        background: linear-gradient(180deg, rgba(255, 255, 255, 0.8) 0%, rgba(249, 250, 251, 0.6) 100%);
        border-radius: 0 0 var(--border-radius-l) var(--border-radius-l);
        position: relative;
    }
    .bg-card {
        background: var(--glass-bg);
        backdrop-filter: var(--blur-sm);
        -webkit-backdrop-filter: var(--blur-sm);
        border: 1px solid var(--glass-border);
        border-radius: var(--border-radius-l);
        box-shadow: var(--shadow-lg);
        padding: 24px 20px;
        margin: 0;
        position: relative;
        overflow: hidden;
    }
    .bg-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.1) 0%, transparent 50%, rgba(255, 255, 255, 0.05) 100%);
        border-radius: inherit;
        pointer-events: none;
    }
    .app-main::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.1) 0%, transparent 100%);
        border-radius: inherit;
        pointer-events: none;
    }
    .main-view {
        display: none;
        animation: viewFadeIn 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    }
    .main-view.active { display: block; }
    @keyframes viewFadeIn {
        from {
            opacity: 0;
            transform: translateY(20px) scale(0.98);
        }
        to {
            opacity: 1;
            transform: translateY(0) scale(1);
        }
    }
    h2 {
        font-size: 1.75em;
        font-weight: 800;
        margin: 0 0 32px 0;
        line-height: 1.2;
        background: linear-gradient(135deg, var(--text-primary) 0%, var(--text-secondary) 100%);
        -webkit-background-clip: text;
        background-clip: text;
        -webkit-text-fill-color: transparent;
        text-align: center;
    }
    h2 .user-name {
        background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-color-light) 100%);
        -webkit-background-clip: text;
        background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .card-menu {
        display: grid;
        grid-template-columns: 1fr;
        gap: 16px;
        margin-top: 2rem;
        position: relative;
    }
    .card-menu::before {
        content: '';
        position: absolute;
        top: -10px;
        left: 50%;
        transform: translateX(-50%);
        width: 60px;
        height: 4px;
        background: linear-gradient(90deg, var(--primary-color), var(--primary-color-light));
        border-radius: 2px;
        opacity: 0.6;
    }
    .menu-card {
        display: flex;
        align-items: center;
        padding: 24px 20px;
        background: var(--glass-bg);
        backdrop-filter: var(--blur-sm);
        -webkit-backdrop-filter: var(--blur-sm);
        border: 1px solid var(--glass-border);
        border-radius: var(--border-radius-l);
        box-shadow: var(--shadow-md);
        cursor: pointer;
        transition: all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94);
        position: relative;
        overflow: hidden;
        margin-bottom: 8px;
        animation: cardSlideIn 0.6s cubic-bezier(0.25, 0.46, 0.45, 0.94) both;
    }
    .menu-card:nth-child(1) { animation-delay: 0.1s; }
    .menu-card:nth-child(2) { animation-delay: 0.2s; }
    .menu-card:nth-child(3) { animation-delay: 0.3s; }
    .menu-card:nth-child(4) { animation-delay: 0.4s; }
    @keyframes cardSlideIn {
        from {
            opacity: 0;
            transform: translateY(30px) scale(0.95);
        }
        to {
            opacity: 1;
            transform: translateY(0) scale(1);
        }
    }
    .menu-card::before {
        content: '';
        position: absolute;
        top: 0;
        left: -100%;
        width: 100%;
        height: 100%;
        background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.15), transparent);
        transition: left 0.6s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    }
    .menu-card:hover::before {
        left: 100%;
    }
    .menu-card:hover {
        transform: translateY(-10px) scale(1.03);
        box-shadow: 0 20px 40px rgba(0, 122, 255, 0.15), 0 8px 32px rgba(0, 0, 0, 0.1);
        border-color: var(--primary-color-light);
        background: linear-gradient(135deg, rgba(255, 255, 255, 0.9) 0%, rgba(249, 250, 251, 0.8) 100%);
    }
    .menu-card:active {
        transform: translateY(-6px) scale(0.97);
        box-shadow: var(--shadow-lg);
        transition-duration: 0.15s;
    }
    .card-icon {
        font-size: 2.2em;
        margin-right: 20px;
        width: 60px;
        height: 60px;
        display: flex;
        justify-content: center;
        align-items: center;
        border-radius: var(--border-radius-m);
        background: linear-gradient(135deg, var(--primary-color-light) 0%, var(--primary-color) 100%);
        color: white;
        box-shadow: 0 8px 20px rgba(0, 122, 255, 0.3);
        position: relative;
        z-index: 1;
    }
    .card-text h3 {
        margin: 0 0 4px 0;
        font-size: 1.1em;
        font-weight: 700;
        color: var(--text-primary);
        line-height: 1.3;
    }
    .card-text p {
        margin: 0;
        font-size: 0.9em;
        color: var(--text-secondary);
        font-weight: 500;
        line-height: 1.4;
    }
        .card-text h3 { margin: 0 0 4px 0; font-size: 1.1em; font-weight: 600; color: var(--text-primary); }
        .card-text p { margin: 0; color: var(--text-secondary); font-size: 0.9em; }
        .form-group { margin-bottom: 18px; }
        .form-group:last-child { margin-bottom: 0; }
        .form-group label { display: block; margin-bottom: 8px; font-weight: 500; font-size: 0.9em; color: var(--text-secondary); }
        .mobile-input { width: 100%; height: 48px; padding: 0 16px; border: 1px solid #e0e0e0; border-radius: var(--border-radius-s); font-size: 1em; font-family: 'Kantumruy Pro', sans-serif; background-color: var(--surface-color); transition: border-color 0.2s ease, box-shadow 0.2s ease, background-color 0.3s ease, color 0.3s ease; -webkit-appearance: none; -moz-appearance: none; appearance: none; }
        select.mobile-input { background-image: url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'%3e%3cpath fill='none' stroke='%23343a40' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M2 5l6 6 6-6'/%3e%3c/svg%3e"); background-repeat: no-repeat; background-position: right 1rem center; background-size: 1em 0.8em; padding-right: 2.5rem; }
        input[type="date"].mobile-input, input[type="time"].mobile-input { line-height: 46px; }
        .mobile-input:focus { border-color: var(--primary-color); box-shadow: 0 0 0 3px rgba(0, 122, 255, 0.25); outline: none; }
        .mobile-input[readonly] { background-color: var(--secondary-color); color: var(--text-secondary); border-color: #e5e5ea; cursor: not-allowed; }
        .mobile-input[readonly]:focus { box-shadow: none; border-color: #e5e5ea; }
        textarea.mobile-input { height: auto; min-height: 120px; padding: 14px 16px; line-height: 1.5; }
        .mobile-button { width: 100%; padding: 15px; border: none; border-radius: var(--border-radius-m); margin-top: 10px; font-size: 1.1em; font-weight: 600; cursor: pointer; text-align: center; text-decoration: none; display: block; transition: background-color 0.2s ease, transform 0.1s ease; }
        .primary-button { background-color: var(--primary-color); color: var(--text-on-primary); box-shadow: 0 4px 12px rgba(0, 122, 255, 0.25); }
        .primary-button:hover { background-color: var(--primary-color-dark); }
        .primary-button:active { transform: scale(0.98); box-shadow: 0 2px 8px rgba(0, 122, 255, 0.2); }
        .back-button { background: none; border: none; color: var(--primary-color); font-size: 1em; font-weight: 500; cursor: pointer; padding: 8px 0; display: inline-flex; align-items: center; margin-bottom: 16px; }
        .back-button i { margin-right: 8px; }
        .form-row { display: flex; gap: 16px; align-items: flex-start; }
        .form-row .form-group { flex: 1; min-width: 0; }
        .request-form-fields { display: none; margin-top: 24px; animation: formFadeIn 0.5s ease-in-out; }
        @keyframes formFadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
        .form-section { background-color: var(--surface-color); border: 1px solid #e5e5ea; border-radius: var(--border-radius-m); padding: 20px; margin-bottom: 20px; box-shadow: var(--shadow-sm); }
        .form-section-header { display: flex; align-items: center; margin-bottom: 20px; padding-bottom: 15px; border-bottom: 1px solid #e5e5ea; }
        .form-section-header i { margin-right: 12px; font-size: 1.2em; color: var(--primary-color); width: 20px; text-align: center; }
        .form-section-header h4 { margin: 0; font-size: 1.1em; font-weight: 600; color: var(--text-primary); }
        #requestForm .mobile-button { margin-top: 20px; }
        .popup-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.7); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); display: none; z-index: 2000; animation: fadeIn 0.3s ease-out; } @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
        .camera-popup-content { background: none; width: 100%; height: 100%; display: flex; flex-direction: column; justify-content: center; align-items: center; }
        #scanner-container { position: relative; width: 100%; height: 100%; background-color: #000; }
        #camera-preview-container { position: absolute; top: 0; left: 0; width: 100%; height: 100%; border-radius: 0; overflow: hidden; }
        #camera-preview { width: 100%; height: 100%; object-fit: cover; }
        /* Full Screen Scanner Frame */
        .scanner-frame { position: absolute; top: 0; left: 0; width: 100%; height: 100%; max-width: none; max-height: none; border-radius: 0; box-shadow: none; z-index: 10; pointer-events: none; }
        /* Corners positioned at edges with padding */
        .scanner-frame .corner { position: absolute; width: 60px; height: 60px;  opacity: 1; margin: 20px; }
        .scanner-frame .top-left { top: 0; left: 0; border-right: none; border-bottom: none; border-top-left-radius: 30px; }
        .scanner-frame .top-right { top: 0; right: 0; border-left: none; border-bottom: none; border-top-right-radius: 30px; }
        .scanner-frame .bottom-left { bottom: 0; left: 0; border-right: none; border-top: none; border-bottom-left-radius: 30px; }
        .scanner-frame .bottom-right { bottom: 0; right: 0; border-left: none; border-top: none; border-bottom-right-radius: 30px; }
        .scanner-laser { position: absolute; top: 20px; left: 20px; right: 20px; height: 3px; background: linear-gradient(90deg, transparent, #ef4444, transparent); box-shadow: 0 0 15px rgba(239, 68, 68, 0.6); border-radius: 5px; animation: scan 2.5s infinite ease-in-out; }
        @keyframes scan { 0%, 100% { top: 20px; opacity: 0.5; } 50% { top: calc(100% - 20px); opacity: 1; } }
        #scanner-ui-elements { width: 100%; text-align: center; color: white; position: relative; z-index: 10; }
        .scanner-text { margin-top: 30px; font-size: 1.1em; text-shadow: 0 1px 3px rgba(0,0,0,0.5); }
        #status_msg_popup { margin-top: 15px; font-weight: 500; min-height: 20px; }
        .close-scanner-btn { position: absolute; top: 25px; right: 25px; font-size: 1.5em; color: var(--text-on-primary); cursor: pointer; width: 44px; height: 44px; background: rgba(0,0,0,0.3); display: flex; align-items: center; justify-content: center; border-radius: 50%; transition: background-color 0.2s ease, transform 0.2s ease; z-index: 20; }
        .close-scanner-btn:hover { background-color: rgba(0,0,0,0.5); transform: scale(1.1); }
        /* NEW: Styles for Select in Popup (Keep it clean and visible) */
        .select-action-container {
            display: flex;
            justify-content: center;
            margin: 0 auto;
            max-width: 250px;
        }
        .select-action-container .mobile-input {
            height: 40px;
            font-size: 0.9em;
            text-align: center;
            border: 2px solid var(--primary-color);
            background-color: var(--surface-color);
            color: var(--text-primary);
        }
        .result-popup-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.4); backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px); display: flex; justify-content: center; align-items: center; z-index: 3000; animation: fadeIn 0.3s; }
        .result-popup-content { background: var(--surface-color); padding: 25px 30px; border-radius: var(--border-radius-l); text-align: center; width: 90%; max-width: 350px; box-shadow: var(--shadow-md); animation: slideIn 0.4s cubic-bezier(0.25, 0.46, 0.45, 0.94); } @keyframes slideIn { from { transform: translateY(30px) scale(0.95); opacity: 0; } to { transform: translateY(0) scale(1); opacity: 1; } }
        .popup-icon { font-size: 4.5em; margin-bottom: 20px; animation: iconPop 0.5s cubic-bezier(0.34, 1.56, 0.64, 1); } @keyframes iconPop { from { transform: scale(0.7); opacity: 0; } to { transform: scale(1); opacity: 1; } }
        .popup-icon .fa-circle-check { color: var(--success-color); } .popup-icon .fa-circle-xmark { color: var(--error-color); }
        .result-popup-content h3 { margin: 0 0 10px; font-size: 1.4em; color: var(--text-primary); font-weight: 600; }
        .result-popup-content p { margin: 0 0 25px; color: var(--text-secondary); font-size: 1em; line-height: 1.5; }
        .popup-close-btn { width: 100%; padding: 13px; border: none; border-radius: var(--border-radius-m); background-color: var(--primary-color); color: white; font-size: 1em; font-weight: 500; cursor: pointer; transition: background-color 0.2s, transform 0.1s; }
        .popup-close-btn:hover { background-color: var(--primary-color-dark); }
        .popup-close-btn:active { transform: scale(0.98); }
            /* ===== VIEW TRANSITION LOADER ===== */
            #viewTransitionOverlay { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; background: radial-gradient(circle at center, rgba(255,255,255,0.85) 0%, rgba(255,255,255,0.6) 60%, rgba(255,255,255,0.35) 100%); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); z-index: 2500; animation: overlayFade .35s ease; }
            @keyframes overlayFade { from { opacity:0; } to { opacity:1; } }
            .vt-loader { width: 74px; height: 74px; position: relative; }
            .vt-loader .ring { position: absolute; inset: 0; border: 6px solid transparent; border-top-color: var(--primary-color); border-radius: 50%; animation: spin 1.2s linear infinite; }
            .vt-loader .ring.r2 { border-top-color: var(--primary-color-light); animation-duration: 1.6s; filter: drop-shadow(0 0 6px rgba(0,122,255,0.5)); }
            .vt-loader .center-dot { position: absolute; top:50%; left:50%; transform: translate(-50%,-50%); width: 18px; height: 18px; background: linear-gradient(135deg,var(--primary-color), var(--primary-color-dark)); border-radius: 50%; box-shadow: 0 4px 14px rgba(0,122,255,0.4); animation: pulse 1.8s ease-in-out infinite; }
            @keyframes spin { to { transform: rotate(360deg); } }
            @keyframes pulse { 0%,100% { transform: translate(-50%,-50%) scale(1); opacity:1; } 50% { transform: translate(-50%,-50%) scale(0.72); opacity:0.7; } }
            #viewTransitionOverlay.fadeout { animation: overlayOut .3s ease forwards; }
            @keyframes overlayOut { to { opacity:0; } }
        /* Style for File Upload Preview */
        .signature-upload-wrapper { position: relative; }
        .signature-file-input { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0; cursor: pointer; z-index: 10; }
        .signature-preview-box { width: 100%; height: 150px; border: 2px dashed #e0e0e0; border-radius: var(--border-radius-s); display: flex; flex-direction: column; justify-content: center; align-items: center; text-align: center; color: var(--text-secondary); background-color: var(--secondary-color); position: relative; overflow: hidden; transition: border-color 0.2s ease; }
        .signature-file-input:hover + .signature-preview-box { border-color: var(--primary-color); }
        .signature-preview-img { max-width: 95%; max-height: 95%; object-fit: contain; }
        .upload-placeholder i { font-size: 2em; margin-bottom: 8px; }
        .upload-placeholder p { margin: 0; font-size: 0.9em; }
        .upload-spinner { border: 4px solid rgba(0, 0, 0, 0.1); width: 36px; height: 36px; border-radius: 50%; border-left-color: var(--primary-color); animation: spin 1s ease infinite; position: absolute; }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }

        /* Submission Loading Styles */
        #submission-loading {
            background: rgba(0, 0, 0, 0.8);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border-radius: 16px;
            padding: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4);
            border: 1px solid rgba(255, 255, 255, 0.1);
            animation: fadeInUp 0.4s ease-out;
            margin: 0 auto;
            max-width: 280px;
        }

        #submission-loading .upload-spinner {
            border: 4px solid rgba(255, 255, 255, 0.2);
            border-left-color: #fff;
            width: 32px;
            height: 32px;
            animation: spin 1s linear infinite;
            margin: 0 auto 12px;
            position: relative;
        }

        #submission-loading p {
            color: #fff;
            font-size: 0.9rem;
            margin: 0;
            text-shadow: 0 1px 2px rgba(0,0,0,0.5);
            font-weight: 500;
        }

        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(15px) scale(0.95);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* Global Loading Overlay Animations */
        @keyframes fadeIn {
            from { opacity: 0; }
            to { opacity: 1; }
        }

        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px) scale(0.95);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* NEW: Signature History Pop-up Styles */
        .history-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 10px;
            max-height: 350px;
            overflow-y: auto;
            padding: 10px;
            border-radius: var(--border-radius-s);
            background-color: var(--secondary-color);
        }
        .history-item {
            background-color: var(--surface-color);
            border: 1px solid #e5e5ea;
            border-radius: var(--border-radius-s);
            padding: 5px;
            text-align: center;
            cursor: pointer;
            transition: transform 0.1s;
        }
        .history-item:hover {
            border-color: var(--primary-color);
            transform: scale(1.02);
        }
        .history-item img {
            max-width: 100%;
            height: 80px;
            object-fit: contain;
        }
        .history-item-date {
            font-size: 0.7em;
            color: var(--text-secondary);
            margin-top: 5px;
        }

/* 4. កែ app-footer: ប្រើ position: fixed; */
.app-footer {
    background: var(--glass-bg);
    backdrop-filter: var(--blur-md);
    -webkit-backdrop-filter: var(--blur-md);
    width: 100%;
    position: fixed;
    bottom: 0;
    left: 50%;
    transform: translateX(-50%);
    max-width: 500px;
    z-index: 999;
    border-top: 1px solid var(--glass-border);
    box-shadow: 0 -8px 32px rgba(0, 0, 0, 0.1);
}
.footer-nav {
    display: flex;
    justify-content: space-around;
    align-items: center;
    padding: 12px 16px 20px 16px;
    background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-color-dark) 100%);
    border-radius: var(--border-radius-l) var(--border-radius-l) 0 0;
    min-height: 64px;
    gap: 8px;
    position: relative;
}
.footer-nav::before {
    content: '';
    position: absolute;
    top: 0;
    left: 50%;
    transform: translateX(-50%);
    width: 120px;
    height: 4px;
    background: rgba(255, 255, 255, 0.3);
    border-radius: 0 0 4px 4px;
}
.footer-btn {
    flex-grow: 0;
    flex-basis: auto;
    text-align: center;
    padding: 8px 6px;
    cursor: pointer;
    color: rgba(255, 255, 255, 0.8);
    transition: all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    border-radius: var(--border-radius-m);
    margin: 0;
    position: relative;
    overflow: hidden;
}
.footer-btn::before {
    content: '';
    position: absolute;
    top: 50%;
    left: 50%;
    width: 0;
    height: 0;
    background: rgba(255, 255, 255, 0.2);
    border-radius: 50%;
    transform: translate(-50%, -50%);
    transition: width 0.3s ease, height 0.3s ease;
}
.footer-btn:active::before {
    width: 120%;
    height: 120%;
}
.footer-btn.active {
    color: white;
    background: rgba(255, 255, 255, 0.15);
    backdrop-filter: var(--blur-sm);
    -webkit-backdrop-filter: var(--blur-sm);
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
    transform: translateY(-2px);
}
.footer-btn:active {
    transform: scale(0.95) translateY(-1px);
}
.footer-btn i {
    font-size: 1.4em;
    margin-bottom: 4px;
    display: block;
    filter: drop-shadow(0 1px 2px rgba(0, 0, 0, 0.1));
}
.footer-btn span {
    font-size: 0.7em;
    font-weight: 600;
    letter-spacing: 0.02em;
    text-transform: uppercase;
}

        /* My Requests View Specific Styles (Existing) */
        .request-status-card {
            background-color: var(--surface-color);
            padding: 15px;
            border-radius: var(--border-radius-m);
            box-shadow: var(--shadow-sm);
            margin-bottom: 16px;
            text-align: center;
            border-left: 5px solid;
            display: flex;
            flex-direction: column;
            align-items: center;
        }
        .status-pending { border-left-color: var(--warning-color); }
        .status-approved { border-left-color: var(--success-color); }
        .status-reject { border-left-color: var(--error-color); }

        .status-card-icon i {
            font-size: 2.2em;
            margin-bottom: 8px;
        }
        .status-pending .status-card-icon i { color: var(--warning-color); }
        .status-approved .status-card-icon i { color: var(--success-color); }
        .status-reject .status-card-icon i { color: var(--error-color); }

        .request-status-card h3 {
            margin: 5px 0 5px 0;
            font-size: 1.2em;
            font-weight: 600;
        }
        .request-status-card p {
            margin: 0;
            font-size: 0.9em;
            color: var(--text-secondary);
        }
        .status-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 16px;
            margin-top: 20px;
        }

        .request-list-placeholder {
            padding: 30px;
            text-align: center;
            color: var(--text-secondary);
        }
        #request-logs-table th, #request-logs-table td {
            padding: 10px 8px;
            text-align: left;
            font-size: 0.9em;
            border-bottom: 1px solid #e5e5ea;
            vertical-align: middle;
        }
        #request-logs-table th {
            background-color: var(--secondary-color);
            color: var(--text-primary);
            font-weight: 600;
        }
        #request-logs-table tr:last-child td {
            border-bottom: none;
        }
        .status-badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 12px;
            font-size: 0.8em;
            font-weight: 600;
            text-align: center;
            min-width: 70px;
        }
        .badge-Pending { background-color: #fff3cd; color: var(--warning-color); }
        .badge-Approved { background-color: #d1e7dd; color: var(--success-color); }
        .badge-Rejected { background-color: #f8d7da; color: var(--error-color); }

        /***************************************/
        /* START: USER PROFILE SIDEBAR STYLES  */
        /***************************************/
        .profile-sidebar-overlay {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0, 0, 0, 0.5);
            z-index: 1999;
            opacity: 0;
            visibility: hidden;
            transition: opacity 0.3s ease, visibility 0.3s ease;
        }
        .profile-sidebar-overlay.active {
            opacity: 1;
            visibility: visible;
        }

        .profile-sidebar {
            position: fixed;
            top: 0;
            right: -100%;
            width: 280px;
            max-width: 80%;
            height: 100%;
            background-color: var(--surface-color);
            z-index: 2000;
            box-shadow: -4px 0 15px rgba(0, 0, 0, 0.1);
            transition: right 0.35s cubic-bezier(0.25, 0.46, 0.45, 0.94);
            display: flex;
            flex-direction: column;
        }

        .profile-sidebar.active {
            right: 0;
        }
        .sidebar-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 15px 20px;
            border-bottom: 1px solid #3a3a3c;
            background-color: var(--primary-color);
            color: white;
        }
        .sidebar-header h3 {
            margin: 0;
            font-size: 1.1em;
            font-weight: 600;
        }
        .close-sidebar-btn {
            background: none;
            border: none;
            font-size: 2em;
            color: white;
            cursor: pointer;
            line-height: 1;
        }
        .sidebar-content {
            padding: 20px;
            flex-grow: 1;
            overflow-y: auto;
        }
        .user-info {
            text-align: center;
            margin-bottom: 20px;
        }
        .user-avatar {
            font-size: 4em;
            color: var(--primary-color);
            margin-bottom: 10px;
        }
        .user-info h4 {
            margin: 0 0 5px 0;
            font-size: 1.2em;
        }
        .user-info p {
            margin: 0;
            color: var(--text-secondary);
            font-size: 0.9em;
        }
        .theme-settings h4 {
            font-size: 1em;
            font-weight: 600;
            margin-bottom: 15px;
            color: var(--text-primary);
        }
        .theme-switcher {
            display: flex;
            border: 1px solid #e0e0e0;
            border-radius: var(--border-radius-s);
            overflow: hidden;
        }
        .theme-btn {
            flex: 1;
            padding: 10px;
            border: none;
            background-color: transparent;
            cursor: pointer;
            font-size: 0.9em;
            font-weight: 500;
            color: var(--text-secondary);
            transition: background-color 0.2s ease, color 0.2s ease;
        }
        .theme-btn.active {
            background-color: var(--primary-color);
            color: white;
        }
        .theme-btn:not(.active):hover {
            background-color: var(--secondary-color);
        }
        .theme-btn i {
            margin-right: 5px;
        }
        /***************************************/
        /* END: USER PROFILE SIDEBAR STYLES    */
        /***************************************/
    </style>
</head>
<body class="mobile-body">
<!-- Global Loading Overlay for Data Submission -->
<div id="global-loading-overlay" style="display: none; position: fixed; inset: 0; background: rgba(0, 0, 0, 0.6); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); z-index: 10000; align-items: center; justify-content: center; animation: fadeIn 0.3s ease-out;">
    <div style="background: rgba(255, 255, 255, 0.98); border-radius: 24px; padding: 32px 40px; box-shadow: 0 25px 80px rgba(0, 0, 0, 0.15), 0 0 0 1px rgba(255, 255, 255, 0.2); text-align: center; max-width: 320px; animation: slideUp 0.4s ease-out; border: 1px solid rgba(0, 0, 0, 0.05);">
        <div style="margin-bottom: 16px;">
            <h3 style="margin: 0; color: var(--text-primary); font-size: 1.2rem; font-weight: 700; letter-spacing: -0.02em; line-height: 1.3;">កំពុងបញ្ជូនទិន្នន័យ</h3>
        </div>
        <p style="margin: 0; color: var(--text-secondary); font-size: 0.95rem; font-weight: 500; opacity: 0.8;">សូមរង់ចាំ កំពុងដំណើរការ...</p>
    </div>
</div>

<div id="pwa-install-prompt" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,0.55); backdrop-filter:blur(6px); -webkit-backdrop-filter:blur(6px); z-index:5000; align-items:center; justify-content:center;">
    <div style="background:#fff; width:90%; max-width:360px; border-radius:20px; padding:26px 26px 22px; box-shadow:0 18px 48px -8px rgba(0,0,0,0.25); position:relative; font-family:'Kantumruy Pro',sans-serif; animation: pwaPop .38s cubic-bezier(.34,1.56,.64,1);">
        <style>
            @keyframes pwaPop { from { transform:translateY(28px) scale(.9); opacity:0;} to { transform:translateY(0) scale(1); opacity:1;} }
            .pwa-btn { display:inline-flex; align-items:center; gap:8px; padding:12px 18px; border-radius:10px; border:none; cursor:pointer; font-weight:600; font-size:.95rem; letter-spacing:.3px; }
            .pwa-btn-primary { background:linear-gradient(135deg,#3498db,#2d82c2); color:#fff; box-shadow:0 4px 14px rgba(52,152,219,.35); }
            .pwa-btn-primary:active { transform:translateY(1px); }
            .pwa-btn-text { background:#ecf0f3; color:#2c3e50; }
            .pwa-close { position:absolute; top:10px; right:10px; background:rgba(0,0,0,0.06); border:none; width:34px; height:34px; border-radius:50%; cursor:pointer; display:flex; align-items:center; justify-content:center; font-size:16px; }
            .pwa-app-icon { width:72px; height:72px; border-radius:22px; box-shadow:0 6px 18px rgba(0,0,0,.2); object-fit:cover; margin-bottom:14px; }
            .pwa-actions { margin-top:20px; display:flex; gap:10px; flex-wrap:wrap; }
            .pwa-title { margin:0 0 6px; font-size:1.15rem; font-weight:700; color:#143451; }
            .pwa-desc { margin:0; font-size:.8rem; color:#4b5b6a; line-height:1.45; }
            @media (max-width:380px){ .pwa-actions { flex-direction:column; } .pwa-btn { width:100%; justify-content:center; } }
        </style>
        <button class="pwa-close" id="pwaDismissBtn" aria-label="Close">×</button>
        <div style="text-align:center; display:flex; flex-direction:column; align-items:center;">
            <img src="icons/icon-192.png" alt="App Icon" class="pwa-app-icon" onerror="this.style.display='none'">
            <h3 class="pwa-title">ដំឡើងកម្មវិធី</h3>
            <p class="pwa-desc">បន្ថែមទៅលើអេក្រង់ដើម ដើម្បីចូលប្រើបានលឿន និងប្រើ Offline បាន។</p>
        </div>
        <div class="pwa-actions">
            <button id="pwaInstallBtn" class="pwa-btn pwa-btn-primary"><i class="fa-solid fa-download"></i> Install</button>
            <button id="pwaLaterBtn" class="pwa-btn pwa-btn-text">ពេលក្រោយ</button>
        </div>
    </div>
</div>
    <div id="offline-bar" style="display: none; background: #ff3b30; color: white; text-align: center; padding: 10px; font-size: 0.9em; font-weight: 700; position: sticky; top: 0; z-index: 10001; box-shadow: 0 4px 12px rgba(255,59,48,0.3);">
        <i class="fas fa-plane-slash" style="margin-right: 8px;"></i> គ្មានប្រព័ន្ធអ៊ីនធឺណិត - កំពុងប្រើ Offline Mode
    </div>
    <div class="app-container">
        <header class="app-header">
            <style>
            /* Scoped header styling for a modern, clean look */
            .app-header .header-content {
                display: flex;
                justify-content: space-between;
                align-items: center;
                gap: 12px;
                padding: 12px 18px;
                background: linear-gradient(90deg, var(--primary-color), var(--primary-color-dark));
                color: #ffffff;
                border-radius: 14px;
                box-shadow: 0 8px 22px rgba(2, 50, 120, 0.12);
                align-items: center;
            }

            .app-header .brand {
                display: flex;
                align-items: center;
                gap: 12px;
            }

            .app-header .header-title {
                margin: 0;
                font-size: 1.05rem;
                font-weight: 700;
                color: #ffffff;
                line-height: 1;
                display: flex;
                align-items: center;
                gap: 10px;
            }

            .app-header .brand img.brand-img {
                width: 46px;
                height: 46px;
                object-fit: cover;
                border-radius: 50%;
                box-shadow: 0 6px 18px rgba(0,0,0,0.18);
                border: 2px solid rgba(255,255,255,0.12);
            }

            .app-header .header-right {
                display: flex;
                align-items: center;
                gap: 12px;
                min-width: 160px;
                justify-content: flex-end;
            }



            .app-header .header-sub {
                display:block;
                font-size:0.78rem;
                color: rgba(255,255,255,0.9);
                margin-top: 2px;
                font-weight: 500;
            }

            .app-header .logout-btn {
                display: inline-flex;
                align-items: center;
                gap: 8px;
                padding: 7px 12px;
                border-radius: 999px;
                background: rgba(255,255,255,0.12);
                color: #fff;
                border: 1px solid rgba(255,255,255,0.14);
                font-weight: 600;
                text-decoration: none;
                transition: transform .12s ease, background .12s ease, box-shadow .12s ease;
                backdrop-filter: blur(4px);
            }

            .app-header .logout-btn i { font-size: 0.9rem; }

            .app-header .logout-btn:hover {
                transform: translateY(-2px);
                background: rgba(255,255,255,0.18);
                box-shadow: 0 6px 18px rgba(0,0,0,0.12);
            }

            .app-header .notification-btn {
                position: relative;
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 36px;
                height: 36px;
                border-radius: 50%;
                background: rgba(255,255,255,0.12);
                color: #fff;
                border: 1px solid rgba(255,255,255,0.14);
                font-size: 1rem;
                cursor: pointer;
                transition: transform .12s ease, background .12s ease, box-shadow .12s ease;
                backdrop-filter: blur(4px);
            }

            .app-header .notification-btn:hover {
                transform: translateY(-2px);
                background: rgba(255,255,255,0.18);
                box-shadow: 0 6px 18px rgba(0,0,0,0.12);
            }

            .notification-badge {
                position: absolute;
                top: -8px;
                right: -8px;
                background: #e74c3c;
                color: white;
                border-radius: 50%;
                width: 18px;
                height: 18px;
                font-size: 0.7rem;
                font-weight: bold;
                display: flex;
                align-items: center;
                justify-content: center;
                border: 2px solid #fff;
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                min-width: 18px;
            }

            .notification-badge.read {
                background: #f39c12;
            }

            .notification-item:hover {
                transform: translateY(-1px);
                box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            }

            .mark-read-btn:hover {
                background: #c0392b !important;
                transform: translateY(-1px);
            }

            @media (max-width: 420px) {

                .app-header .header-content { padding: 10px 12px; border-radius: 10px; }
                .app-header .header-title { font-size: 1rem; }
            }
            </style>

            <div class="header-content">
            <div class="brand">
                <h1 class="header-title" aria-label="App title">
                <?php
                $header_type = get_setting('header_type', 'title');
                $header_logo_path = get_setting('header_logo_path', '');

                if ($header_type === 'logo' && !empty($header_logo_path) && file_exists($header_logo_path)) {
                    echo '<img src="' . htmlspecialchars($header_logo_path) . '" alt="Logo" class="brand-img">';
                }
                echo '<span>' . htmlspecialchars(get_setting_typed('header_title', 'Attendance')) . '</span>';
                ?>
                </h1>
                <?php if ($subtitle = get_setting_typed('header_subtitle', '')): ?>
                <div class="header-sub"><?php echo htmlspecialchars($subtitle); ?></div>
                <?php endif; ?>
            </div>

            <?php if ($is_logged_in): ?>
                <div class="header-right" role="navigation" aria-label="User actions">


                <div class="notification-btn" title="Notifications">
                    <i class="fas fa-bell" aria-hidden="true"></i>
                    <span id="notificationBadge" class="notification-badge" style="display: none;"></span>
                </div>

                <a href="?logout=1" class="logout-btn" title="ចាកចេញ">
                    <i class="fas fa-right-from-bracket" aria-hidden="true"></i>
                    <span>ចាកចេញ</span>
                </a>


                </div>
            <?php endif; ?>
            </div>
        </header>
        <main class="app-main">
            <div class="bg-card">
                <?php if (!$is_logged_in): ?>
                <div id="login-view" class="main-view active">
                    <div class="login-icon"><i class="fas fa-fingerprint"></i></div>
                    <h2>ចូលប្រព័ន្ធ</h2>
                    <p style="color: var(--text-secondary); margin-top: -15px; margin-bottom: 30px;">សូមបញ្ចូលលេខសម្គាល់បុគ្គលិករបស់អ្នក</p>
                    <form id="qrLoginForm" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="post" style="width:100%;">
                        <input type="hidden" name="login_id" value="1">
                        <!-- NEW: User type selector (Skill / Worker) -->
                        <div class="form-group" style="margin-bottom:16px;">
                            <label style="display:block; text-align:left; font-size:0.85em; color:var(--text-secondary); margin-bottom:6px;">ប្រភេទអ្នកប្រើ (Type)</label>
                            <div style="display:flex; gap:12px;">
                                <label style="flex:1; display:flex; align-items:center; gap:6px; background:var(--secondary-color); padding:10px 12px; border:1px solid #e0e0e0; border-radius:10px; cursor:pointer;">
                                    <input type="radio" name="scan_user_type" value="skill" required style="accent-color: var(--primary-color);"> <span style="font-size:0.85em; font-weight:600;">ជំនាញ (Skill)</span>
                                </label>
                                <label style="flex:1; display:flex; align-items:center; gap:6px; background:var(--secondary-color); padding:10px 12px; border:1px solid #e0e0e0; border-radius:10px; cursor:pointer;">
                                    <input type="radio" name="scan_user_type" value="worker" required style="accent-color: var(--primary-color);"> <span style="font-size:0.85em; font-weight:600;">កម្មករ (Worker)</span>
                                </label>
                            </div>
                        </div>
                        <div class="form-group">
                            <input type="text" id="employee_id" name="employee_id" class="mobile-input" placeholder="Employee ID" required>
                        </div>
                        <button type="submit" class="mobile-button primary-button">ចូល</button>
                    </form>
                </div>

               <?php else: ?>
                <div id="card-menu-view" class="main-view active">
                    <h2><?php echo htmlspecialchars(get_setting_typed('greeting_text', 'សួស្តី')); ?>, <span class="user-name"><?php echo htmlspecialchars($user_data['name'] ?? ''); ?>!</span></h2>

                    <div class="card-menu">
                        <?php if (get_setting_typed('show_attendance_card', '1') == '1'): ?>
                        <div class="menu-card" onclick="startAttendanceProcess()">
                            <div class="card-icon"><i class="fas fa-qrcode"></i></div>
                            <div class="card-text"><h3><?php echo htmlspecialchars(get_setting_typed('label_attendance', 'Attendance')); ?></h3><p>ស្កេន QR Code សម្រាប់វត្តមាន</p></div>
                        </div>
                        <?php endif; ?>

                        <?php if (get_setting_typed('show_request_form_card', '0') == '1'): ?>
                        <div class="menu-card" onclick="footerNavigate(null, 'request-form-view')">
                            <div class="card-icon"><i class="fas fa-file-lines"></i></div>
                            <div class="card-text"><h3><?php echo htmlspecialchars(get_setting_typed('label_request_form', 'Request Form')); ?></h3><p>ស្នើសុំច្បាប់, OT, និងផ្សេងៗ</p></div>
                        </div>
                        <?php endif; ?>

                        <?php if (get_setting_typed('show_my_requests_card', '1') == '1'): ?>
                        <div class="menu-card" onclick="footerNavigate(null, 'my-requests-view')">
                            <div class="card-icon"><i class="fas fa-clock-rotate-left"></i></div>
                            <div class="card-text"><h3><?php echo htmlspecialchars(get_setting_typed('label_my_requests', 'My Requests')); ?></h3><p>មើលស្ថានភាពសំណើរបស់អ្នក</p></div>
                        </div>
                        <?php endif; ?>

                        <?php if (get_setting_typed('show_view_logs_card', '1') == '1'): ?>
                        <div class="menu-card" onclick="footerNavigate(null, 'my-logs-view')">
                            <div class="card-icon"><i class="fas fa-clipboard-list"></i></div>
                            <div class="card-text"><h3><?php echo htmlspecialchars(get_setting_typed('label_view_logs', 'View Logs')); ?></h3><p>មើលកំណត់ត្រាវត្តមានរបស់អ្នក</p></div>
                        </div>
                        <?php endif; ?>
                    </div>
                </div>


                <div id="request-form-view" class="main-view">
                    <style>
                        /* Compact, scrollable form layout with sticky submit action */
                        .request-form-layout {
                            display: flex;
                            flex-direction: column;
                            height: calc(100vh - var(--header-height) - var(--footer-height) - 32px); /* leave breathing room */
                            max-height: calc(100vh - var(--header-height) - var(--footer-height) - 32px);
                            background: transparent;
                            gap: 12px;
                        }
                        .request-form-body {
                            overflow: auto;
                            -webkit-overflow-scrolling: touch;
                            padding: 12px;
                            flex: 1 1 auto;
                        }
                        /* Ensure each .form-section has consistent spacing inside the scrollable area */
                        .request-form-body .form-section { margin-bottom: 14px; }
                        /* Sticky action bar so the submit button is always visible */
                        .request-form-actions {
                            position: sticky;
                            bottom: 7rem;
                            background: linear-gradient(180deg, rgba(255,255,255,0.95), rgba(250,250,252,0.9));
                            border-top: 1px solid rgba(0,0,0,0.04);
                            padding: 10px 12px;
                            display: flex;
                            gap: 10px;
                            align-items: center;
                            justify-content: space-between;
                            box-shadow: 0 -6px 18px rgba(6,24,80,0.04);
                            z-index: 50;
                            flex-shrink: 0;
                        }
                        /* Make submit button full width on small screens */
                        .request-form-actions .mobile-button {
                            flex: 1 1 auto;
                            min-width: 120px;
                        }
                        /* Small helper: shrink long form labels a bit */
                        .request-form-body .form-group label { font-size: 0.95rem; }
                        @media (max-width:420px) {
                            .request-form-layout { padding-bottom: env(safe-area-inset-bottom); }
                            .request-form-actions { padding: 14px 12px; }
                        }
                    </style>

                    <button class="back-button" onclick="footerNavigate(null, 'card-menu-view')"><i class="fas fa-arrow-left"></i>ត្រឡប់ក្រោយ</button>
                    <h2>ទម្រង់ស្នើសុំ</h2>

                    <!-- New layout: scrollable body + sticky actions -->
                    <div class="request-form-layout" role="region" aria-label="Request form container">
                        <div class="request-form-body">
                            <form id="requestForm" onsubmit="submitRequest(event)">
                                <div class="form-section">
                                    <div class="form-group">
                                        <label for="requestType">ប្រភេទសំណើ</label>
                                        <select id="requestType" name="requestType" class="mobile-input" required>
                                            <option value="" disabled selected>-- សូមជ្រើសរើស --</option>
                                            <option value="Leave">Leave (សុំច្បាប់)</option>
                                            <option value="Overtime">Overtime (OT)</option>
                                            <option value="Forget-Attendance">Forget Attendance (ភ្លេចស្កេន)</option>
                                            <option value="Late">Late (មកយឺត)</option>
                                            <option value="Change-Day-Off">Change Day Off (ប្តូរថ្ងៃសម្រាក)</option>
                                        </select>
                                    </div>
                                </div>

                                <div id="dynamic-form-container">

                                    <div id="form-Leave" class="request-form-fields">
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-user"></i><h4>ព័ត៌មានបុគ្គលិក</h4></div>
                                            <div class="form-row">
                                                <div class="form-group"><label>ឈ្មោះ</label><input type="text" name="leave_name" class="mobile-input" value="<?php echo htmlspecialchars($user_data['name'] ?? ''); ?>" readonly></div>
                                                <div class="form-group"><label>អត្តលេខ</label><input type="text" name="leave_employee_id" class="mobile-input" value="<?php echo htmlspecialchars($user_data['employee_id'] ?? ''); ?>" readonly></div>
                                            </div>
                                            <!-- [កូដដែលបានកែសម្រួល] ស្វែងរក Key 'position' (អង់គ្លេស) ឬ 'មុខតំណែង' (ខ្មែរ) -->
                                            <div class="form-group"><label>តួនាទី</label><input type="text" name="leave_position" class="mobile-input" value="<?php echo htmlspecialchars($custom_data['position'] ?? $custom_data['មុខតំណែង'] ?? ''); ?>" readonly></div>
                                        </div>
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-calendar-day"></i><h4>ព័ត៌មានលម្អិត</h4></div>
                                            <div class="form-group"><label>ថ្ងៃស្នើសុំ</label><input type="date" name="leave_date" class="mobile-input" required></div>
                                            <div class="form-group"><label>ថ្ងៃធ្វើសង</label><input type="date" name="leave_makeup_date" class="mobile-input"></div>
                                            <div class="form-row">
                                                <div class="form-group"><label>ចំនួនម៉ោងសង</label><input type="number" name="leave_makeup_hours" class="mobile-input" placeholder="ឧ. 2"></div>
                                                <div class="form-group"><label>ម៉ោងសរុបសង</label><input type="number" name="leave_total_hours" class="mobile-input" placeholder="ឧ. 8"></div>
                                            </div>
                                            <div class="form-group"><label>ប្រគល់ការងារឱ្យ</label><input type="text" name="leave_handoff" class="mobile-input"></div>
                                            <div class="form-group"><label>លេខទំនាក់ទំនង</label><input type="tel" name="leave_contact" class="mobile-input" required></div>
                                            <div class="form-group"><label>មូលហេតុ</label><textarea rows="4" name="leave_reason" class="mobile-input" placeholder="សូមសរសេរពីមូលហេតុ..." required></textarea></div>
                                        </div>
                                        <!-- Signature input removed per request: no signature required for Leave -->
                                    </div>

                                    <div id="form-Overtime" class="request-form-fields">
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-user"></i><h4>ព័ត៌មានបុគ្គលិក</h4></div>
                                            <div class="form-row">
                                                <div class="form-group"><label>ឈ្មោះ</label><input type="text" name="ot_name" class="mobile-input" value="<?php echo htmlspecialchars($user_data['name'] ?? ''); ?>" readonly></div>
                                                <div class="form-group"><label>អត្តលេខ</label><input type="text" name="ot_employee_id" class="mobile-input" value="<?php echo htmlspecialchars($user_data['employee_id'] ?? ''); ?>" readonly></div>
                                            </div>
                                            <!-- [កូដដែលបានកែសម្រួល] ស្វែងរក Key 'position' (អង់គ្លេស) ឬ 'មុខតំណែង' (ខ្មែរ) -->
                                            <div class="form-group"><label>តួនាទី</label><input type="text" name="ot_position" class="mobile-input" value="<?php echo htmlspecialchars($custom_data['position'] ?? $custom_data['មុខតំណែង'] ?? ''); ?>" readonly></div>
                                        </div>
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-clock"></i><h4>ព័ត៌មានលម្អិត OT</h4></div>
                                            <div class="form-group"><label>ថ្ងៃធ្វើ OT</label><input type="date" name="ot_date" class="mobile-input" required></div>
                                            <div class="form-row">
                                                <div class="form-group"><label>ម៉ោងចាប់ផ្តើម</label><input type="time" name="ot_start_time" class="mobile-input" required></div>
                                                <div class="form-group"><label>ម៉ោងបញ្ចប់</label><input type="time" name="ot_end_time" class="mobile-input" required></div>
                                            </div>
                                            <div class="form-group"><label>មូលហេតុ/ការងារ</label><textarea rows="4" name="ot_reason" class="mobile-input" placeholder="សូមសរសេរពីការងារដែលត្រូវធ្វើ..." required></textarea></div>
                                        </div>
                                        <!-- Signature input removed per request: no signature required for Overtime -->
                                    </div>

                                    <div id="form-Forget-Attendance" class="request-form-fields">
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-history"></i><h4>ព័ត៌មានភ្លេចស្កេន</h4></div>
                                            <div class="form-group">
                                                <label for="forgetType">ប្រភេទដែលភ្លេច</label>
                                                <select id="forgetType" name="forgetType" class="mobile-input" required>
                                                    <option value="" disabled selected>-- ជ្រើសរើស --</option>
                                                    <option value="Check-In">Check-In</option>
                                                    <option value="Check-Out">Check-Out</option>
                                                    <option value="Both">ទាំងពីរ</option>
                                                </select>
                                            </div>
                                            <div class="form-group">
                                                <label for="forget_date">ថ្ងៃដែលភ្លេច</label>
                                                <input type="date" id="forget_date" name="forget_date" class="mobile-input" required>
                                            </div>
                                            <div id="time-inputs-container" style="display:none;">
                                                <div class="form-row">
                                                    <div id="check-in-time-group" class="form-group" style="display:none;"><label>ម៉ោង Check-In</label><input type="time" name="forget_check_in_time" class="mobile-input"></div>
                                                    <div id="check-out-time-group" class="form-group" style="display:none;"><label>ម៉ោង Check-Out</label><input type="time" name="forget_check_out_time" class="mobile-input"></div>
                                                </div>
                                            </div>
                                            <div id="forgot-count-group" class="form-group" style="display:none;">
                                                <label for="forgot_count">ចំនួនដងដែលភ្លេច (Total)</label>
                                                <input type="number" id="forgot_count" name="forgot_count" class="mobile-input" placeholder="ឧ. 1" min="1">
                                            </div>
                                            <div class="form-group"><label>មូលហេតុ</label><textarea rows="4" name="forget_reason" class="mobile-input" placeholder="សូមសរសេរពីមូលហេតុ..." required></textarea></div>
                                        </div>
                                        <!-- Signature input removed per request: no signature required for Forget-Attendance -->
                                    </div>

                                    <div id="form-Late" class="request-form-fields">
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-hourglass-start"></i><h4>ព័ត៌មានមកយឺត</h4></div>
                                            <div class="form-group">
                                                <label for="late_date">ថ្ងៃដែលមកយឺត</label>
                                                <input type="date" id="late_date" name="late_date" class="mobile-input" required>
                                            </div>
                                            <div class="form-group">
                                                <label for="actual_check_in_time">ម៉ោងចូលធ្វើការជាក់ស្តែង</label>
                                                <input type="time" id="actual_check_in_time" name="actual_check_in_time" class="mobile-input" required>
                                            </div>
                                            <div class="form-group"><label>មូលហេតុ</label><textarea rows="4" name="late_reason_text" class="mobile-input" placeholder="សូមសរសេរពីមូលហេតុ..." required></textarea></div>
                                        </div>
                                        <!-- Signature input removed per request: no signature required for Late -->
                                    </div>

                                    <div id="form-Change-Day-Off" class="request-form-fields">
                                        <div class="form-section">
                                            <div class="form-section-header"><i class="fas fa-sync"></i><h4>ប្តូរថ្ងៃសម្រាក</h4></div>
                                            <div class="form-group"><label>ថ្ងៃសម្រាកដើម</label><input type="date" name="original_day_off" class="mobile-input" required></div>
                                            <div class="form-group"><label>ថ្ងៃធ្វើការជំនួស</label><input type="date" name="new_work_day" class="mobile-input" required></div>
                                            <div class="form-group"><label>ថ្ងៃសម្រាកថ្មី</label><input type="date" name="new_day_off" class="mobile-input" required></div>
                                            <div class="form-group"><label>មូលហេតុ</label><textarea rows="4" name="change_day_off_reason" class="mobile-input" placeholder="សូមសរសេរពីមូលហេតុ..." required></textarea></div>
                                        </div>
                                        <!-- Signature input removed per request: no signature required for Change-Day-Off -->
                                    </div>

                                </div>

                                <!-- keep the form open but move submit to sticky actions -->
                            </form>
                        </div>

                        <!-- Sticky actions (submit tied to form by form="requestForm") -->
                        <div class="request-form-actions" aria-hidden="false">
                            <button type="button" class="mobile-button" onclick="footerNavigate(null, 'card-menu-view')">បោះចោល</button>
                            <button type="submit" form="requestForm" class="mobile-button primary-button">ដាក់ស្នើ</button>
                        </div>
                    </div>
                </div>

                <div id="my-requests-view" class="main-view">
                    <h2>សំណើរបស់ខ្ញុំ</h2>
                    <div class="status-grid">
                        <div class="request-status-card status-pending">
                            <div class="status-card-icon"><i class="fas fa-hourglass-half"></i></div>
                            <h3>កំពុងរង់ចាំ</h3>
                            <p id="pending-count"><?php echo $request_counts['Pending']; ?> សំណើ</p>
                        </div>
                        <div class="request-status-card status-approved">
                            <div class="status-card-icon"><i class="fas fa-check-circle"></i></div>
                            <h3>បានអនុម័ត</h3>
                            <p id="approved-count"><?php echo $request_counts['Approved']; ?> សំណើ</p>
                        </div>
                        <div class="request-status-card status-reject">
                            <div class="status-card-icon"><i class="fas fa-times-circle"></i></div>
                            <h3>មិនអនុម័ត</h3>
                            <p id="rejected-count"><?php echo $request_counts['Rejected']; ?> សំណើ</p>
                        </div>
                    </div>

                    <h3 style="margin-top: 30px; font-weight: 600; font-size: 1.2em;">កំណត់ត្រាសំណើថ្មីៗ</h3>
                    <div id="request-list-container" class="form-section" style="padding: 10px; margin-top: 10px;">
                        <div class="request-list-placeholder" id="request-list-loading" style="display:none; text-align:center; padding: 20px;">
                            <div class="upload-spinner" style="position: relative; margin: 0 auto 10px; border: 4px solid rgba(0, 122, 255, 0.2); border-left-color: var(--primary-color);"></div>
                            <p>កំពុងទាញយកកំណត់ត្រា...</p>
                        </div>
                        <div class="request-list-placeholder" id="request-list-empty">
                            <i class="fas fa-folder-open" style="margin-right: 5px;"></i>
                            មិនមានកំណត់ត្រាសំណើទេ។
                        </div>
                        <table id="request-logs-table" style="width: 100%; border-collapse: collapse; display: none;">
                            </table>
                    </div>
                </div>

                <div id="my-logs-view" class="main-view">
                    <h2>កំណត់ត្រាវត្តមាន</h2>
                    <div class="form-section">
                        <div class="date-filter-group" style="display: flex; gap: 10px; margin-bottom: 20px;">
                            <input type="date" id="log-selected-date" class="mobile-input" value="<?php echo date('Y-m-d'); ?>" style="flex: 1;">
                            <button type="button" class="mobile-button" onclick="loadAttendanceLogs()" style="width: auto; padding: 0 20px;">មើល</button>
                        </div>

                        <div id="logs-list-container">
                            <div class="request-list-placeholder" id="logs-list-loading" style="display:none; text-align:center; padding: 20px;">
                                <div class="upload-spinner" style="position: relative; margin: 0 auto 10px; border: 4px solid rgba(0, 122, 255, 0.2); border-left-color: var(--primary-color);"></div>
                                <p>កំពុងទាញយកកំណត់ត្រា...</p>
                            </div>
                            <div class="request-list-placeholder" id="logs-list-empty">
                                <i class="fas fa-calendar-times" style="margin-right: 5px;"></i>
                                មិនមានកំណត់ត្រាវត្តមានសម្រាប់ថ្ងៃនេះទេ។
                            </div>
                            <div id="attendance-logs-content"></div>
                        </div>
                    </div>
                </div>


                <div id="my-locations-view" class="main-view">
                    <h2>ទីតាំងដែលបានអនុញ្ញាត</h2>
                    <div id="locations-list-container" class="form-section">
                        <div class="request-list-placeholder" id="locations-list-loading" style="display:none; text-align:center; padding: 20px;">
                            <div class="upload-spinner" style="position: relative; margin: 0 auto 10px; border: 4px solid rgba(0, 122, 255, 0.2); border-left-color: var(--primary-color);"></div>
                            <p>កំពុងទាញយកទីតាំង...</p>
                        </div>
                        <div class="request-list-placeholder" id="locations-list-empty" style="display:none;">
                            <i class="fas fa-map-marker-slash" style="margin-right: 5px;"></i>
                            មិនមានទីតាំងណាមួយត្រូវបានចុះឈ្មោះទេ។
                        </div>
                        <div id="locations-list-content"></div>
                    </div>
                </div>

                <form id="checkForm" method="post" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" style="display:none;">
                        <input type="hidden" id="qr_location_id" name="qr_location_id">
                        <input type="hidden" id="qr_secret" name="qr_secret">
                        <input type="hidden" id="user_location_raw" name="user_location_raw">
                        <input type="hidden" id="action" name="action">
                        <input type="hidden" id="area" name="area" value="N/A">
                        <input type="hidden" id="late_reason" name="late_reason" value="">
                        <!-- [កូដដែលបានកែសម្រួល] ប្រើ Coalescing Operator ដើម្បីបំពេញ value ឱ្យបានត្រឹមត្រូវ ទោះ Key ជាភាសាអ្វីក៏ដោយ -->
                        <input type="hidden" id="workplace" name="workplace" value="<?php echo htmlspecialchars($custom_data['workplace'] ?? $custom_data['workplace_name'] ?? $custom_data['department'] ?? $custom_data['នាយកដ្ឋាន'] ?? 'N/A'); ?>">
                        <input type="hidden" id="branch" name="branch" value="<?php echo htmlspecialchars($custom_data['branch'] ?? $custom_data['branch_name'] ?? $custom_data['សាខា'] ?? 'N/A'); ?>">
                </form>
            <?php endif; ?>
            </div>
        </main>
    </div>

    <?php if ($is_logged_in): ?>
    <footer class="app-footer" role="navigation" aria-label="Footer navigation">
        <!-- View transition loader overlay -->
        <div id="viewTransitionOverlay" aria-hidden="true">
            <div class="vt-loader" role="status" aria-label="Loading">
                <div class="ring r1"></div>
                <div class="ring r2"></div>
                <div class="center-dot"></div>
            </div>
        </div>
        <style>
            /* iOS-inspired footer (iOS 26 aesthetic: frosted glass, soft depth, large touch targets) */
            .app-footer {
                padding: calc(8px + env(safe-area-inset-bottom));
                backdrop-filter: blur(14px) saturate(140%);
                -webkit-backdrop-filter: blur(14px) saturate(140%);
                background: linear-gradient(180deg, rgba(255,255,255,0.50), rgba(245,245,250,0.36));
                border: 1px solid rgba(255,255,255,0.48);
                border-radius: 22px;
                box-shadow: 0 10px 30px rgba(12,24,60,0.12), inset 0 1px 0 rgba(255,255,255,0.6);
                width: calc(100% - 24px);
                max-width: 520px;
                left: 50%;
                transform: translateX(-50%);
                position: fixed;
                bottom: 12px;
                z-index: 1200;
                overflow: visible;
            }


            /* footer nav pill - balanced grid so buttons share width equally */
            .app-footer .footer-nav {
                display: flex;                  /* switch to flex so content width can shrink when few */
                gap: 10px;
                padding: 10px 14px;
                border-radius: 18px;
                background: linear-gradient(180deg, rgba(255,255,255,0.06), rgba(0,0,0,0.02));
                width: 100%;
                align-items: center;
                justify-content: center;        /* center group */
                flex-wrap: nowrap;              /* keep in one row */
            }

            /* When only 1 or 2 buttons remain visible, center them nicely and keep compact width */
            .app-footer .footer-nav.is-1 .footer-btn,
            .app-footer .footer-nav.is-2 .footer-btn,
            .app-footer .footer-nav.is-3 .footer-btn { flex: 0 0 auto; }
            .app-footer .footer-nav.is-1 { gap: 0; }
            .app-footer .footer-nav.is-1 .footer-btn { width: var(--footer-btn-size); }
            .app-footer .footer-nav.is-2 { gap: 16px; }
            .app-footer .footer-nav.is-2 .footer-btn { width: var(--footer-btn-size); }
            .app-footer .footer-nav.is-3 { gap: 18px; }
            .app-footer .footer-nav.is-3 .footer-btn { width: var(--footer-btn-size); }
            /* 4+ buttons: let them distribute */
            .app-footer .footer-nav:not(.is-1):not(.is-2):not(.is-3) .footer-btn { flex: 1 1 0; }

            /* Central Manual Attendance Button - Floating Action Button Style */
            .manual-attendance-btn {
                position: absolute;
                top: -90px;
                z-index: 999;
                right: 10px;
                width: 72px !important;
                height: 72px !important;
                border-radius: 50% !important;
                background: linear-gradient(135deg, var(--primary-color) 0%, var(--primary-color-dark) 100%) !important;
                box-shadow: 0 8px 24px rgba(0, 122, 255, 0.4), 0 4px 12px rgba(0, 0, 0, 0.2);
                border: 3px solid rgba(255, 255, 255, 0.9);
                z-index: 1260;
                transition: all 0.3s cubic-bezier(0.25, 0.46, 0.45, 0.94);
                --footer-icon-size: 32px;
                animation: floatUpDown 3s ease-in-out infinite;
            }
            @keyframes floatUpDown {
                0%, 100% {
                    transform: translateY(0);
                }
                50% {
                    transform: translateY(-10px);
                }
            }
            .manual-attendance-btn:hover,
            .manual-attendance-btn:active {
                transform: scale(1.1);
                box-shadow: 0 12px 32px rgba(0, 122, 255, 0.5), 0 6px 16px rgba(0, 0, 0, 0.3);
            }
            .manual-attendance-btn i {
                background: rgba(255, 255, 255, 0.9) !important;
                color: var(--primary-color) !important;
                border-radius: 50%;
                z-index: 9999;
                width: 32px !important;
                height: 32px !important;
                display: flex !important;
                align-items: center !important;
                justify-content: center !important;
                font-size: 16px !important;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
            }
            .manual-attendance-btn span {
                position: absolute;
                top: 50%;
                right: 85px;
                transform: translateY(-50%);
                font-size: 0.65rem;
                font-weight: 700;
                color: var(--primary-color);
                background: rgba(255, 255, 255, 0.95);
                padding: 4px 10px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0, 0, 0, 0.1);
                white-space: nowrap;
                opacity: 0;
                transition: opacity 0.3s ease;
                pointer-events: none;
            }
            .manual-attendance-btn:hover span {
                opacity: 1;
            }

            /* Floating text above the button */
            .manual-attendance-btn::after {
                content: "(ស្កេនវត្តមានរហ័ស)";
                position: absolute;
                top: -25px;
                left: 50%;
                transform: translateX(-50%);
                font-size: 0.65rem;
                font-weight: 600;
                color: var(--primary-color);
                background: rgba(255, 255, 255, 0.95);
                padding: 4px 10px;
                border-radius: 12px;
                box-shadow: 0 3px 10px rgba(0, 0, 0, 0.15);
                white-space: nowrap;
                opacity: 1;
                pointer-events: none;
                backdrop-filter: blur(4px);
                -webkit-backdrop-filter: blur(4px);
                border: 1px solid rgba(255, 255, 255, 0.3);
                z-index: 1220;
            }

            /* Adjust footer nav to accommodate central button */
            .app-footer .footer-nav {
                padding-top: 10px;
                position: relative;
            }

            /* each footer button: occupy full column, center content, consistent sizing */
            .app-footer .footer-btn {
                display: inline-flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                gap: 5px;
                width: 100%;
                height: var(--footer-btn-size);
                padding: 6px 4px;
                border-radius: 16px;
                color: var(--text-secondary);
                text-decoration: none;
                font-weight: 700;
                font-size: 0.65rem;
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
                cursor: pointer;
                border: none;
            }

            .app-footer .footer-btn.active {
                color: var(--primary-color);
                transform: translateY(-2px);
            }

            .app-footer .footer-btn i {
                font-size: 1.25rem;
                margin-bottom: 2px;
                transition: all 0.3s ease;
            }

            .app-footer .footer-btn.active i {
                transform: scale(1.15);
                filter: drop-shadow(0 4px 8px rgba(0, 122, 255, 0.3));
            }

            /* Dark mode nav footer */
            html[data-theme='dark'] .app-footer {
                background: linear-gradient(180deg, rgba(28, 28, 30, 0.94), rgba(10, 10, 10, 0.98));
                border-color: rgba(255, 255, 255, 0.08);
            }
                font-size: calc(var(--footer-icon-size) * 0.55);
                line-height: var(--footer-icon-size);
                transition: transform .12s ease, box-shadow .12s ease, background .12s ease;
            }

            /* label */
            .app-footer .footer-btn span {
                font-size: 0.68rem;
                color: rgba(10,10,10,0.65);
                line-height: 1;
                display: block;
                white-space: nowrap;
                overflow: hidden;
                text-overflow: ellipsis;
                max-width: 100%;
            }

            /* hover / touch feedback */
            .app-footer .footer-btn:active,
            .app-footer .footer-btn:hover {
                box-shadow: 0 18px 40px rgba(6,24,80,0.12);
            }

            /* active state (iOS accent) */
            .app-footer .footer-btn.active {
                background: linear-gradient(180deg, rgba(0,122,255,0.12), rgba(0,122,255,0.06));
                color: white;
                border: 1px solid rgba(255,255,255,0.6);
                box-shadow: 0 14px 34px rgba(0,122,255,0.14), inset 0 1px 0 rgba(255,255,255,0.35);
            }

            .app-footer .footer-btn.active i,
            .app-footer .footer-btn.active svg,
            .app-footer .footer-btn.active .fa {
                background: linear-gradient(180deg, var(--primary-color), var(--primary-color-dark));
                color: #fff;
                transform: translateY(-3px) scale(1.06);
                box-shadow: 0 10px 28px rgba(0,122,255,0.22);
            }




            /* accessibility: increase hit area on very small screens */
            @media (max-width: 420px) {
                .app-footer { bottom: 8px; width: calc(100% - 18px); --footer-btn-size: 58px; --footer-icon-size: 38px; }
                .app-footer .footer-btn { width: var(--footer-btn-size); height: var(--footer-btn-size); }
                .app-footer .footer-btn span { font-size: 0.62rem; color: rgba(10,10,10,0.7); }
            }

            /* respects very small devices notch */
            @supports (padding: max(0px)) {
                .app-footer { padding-bottom: calc(12px + env(safe-area-inset-bottom)); }
            }

             .latest-scans-panel {
                position: fixed;
                left: 50%;
                transform: translateX(-50%);
                /* Move panel a bit higher so it doesn't look stuck to footer */
                bottom: calc(24px + var(--footer-height));
                z-index: 1250;
                width: calc(100% - 28px);
                max-width: 520px;
                pointer-events: none; /* container ignores pointer, items remain interactive */
                /* maximum visible height so it never grows and overlaps main content too much */
                --latest-scans-max-height: min(56vh, 520px);
            }
            .latest-scans-header {
                font-size: 0.70rem;
                font-weight: 600;
                letter-spacing: .5px;
                text-transform: uppercase;
                color: var(--text-secondary);
                padding: 0 4px 4px 4px;
                display: flex;
                align-items: center;
                gap: 6px;
                user-select: none;
            }
            .latest-scans-header .icon {
                width: 18px; height: 18px; display:flex; align-items:center; justify-content:center; color: var(--primary-color);
            }
            .latest-scans-panel .list {
                display: flex;
                flex-direction: column;
                gap: 8px;
                /* keep the list from growing indefinitely; make it scrollable when long */
                max-height: var(--latest-scans-max-height);
                overflow-y: auto;
                padding: 6px; /* breathing room for scrollable content */
                box-sizing: border-box;
                -webkit-overflow-scrolling: touch; /* smooth scrolling on iOS */
                overscroll-behavior: contain; /* avoid body scroll while scrolling this panel */
            }

            /* Custom scrollbar (subtle) */
            .latest-scans-panel .list::-webkit-scrollbar { width: 10px; }
            .latest-scans-panel .list::-webkit-scrollbar-track { background: transparent; }
            .latest-scans-panel .list::-webkit-scrollbar-thumb { background: rgba(0,0,0,0.10); border-radius: 8px; }
            .latest-scans-item {
                pointer-events: auto;
                background: linear-gradient(180deg, rgba(255,255,255,0.98), rgba(250,250,252,0.95));
                border: 1px solid rgba(0,0,0,0.06);
                border-radius: 12px;
                padding: 10px 12px;
                box-shadow: 0 8px 26px rgba(2,24,80,0.06);
                display: flex;
                gap: 10px;
                align-items: center;
                font-size: 0.95rem;
            }
            .latest-scans-item .meta { color: var(--text-secondary); font-size: 0.88rem; }
            .latest-scans-item .title { font-weight: 700; color: var(--text-primary); }
            @media (max-width:420px) {
                .latest-scans-panel { bottom: calc(20px + var(--footer-height)); width: calc(100% - 18px); }
                .latest-scans-item { padding: 8px 10px; }
            }
            /* Small device adjustments to avoid overlapping the card above (very narrow screens) */
            @media (max-width:360px) {
                .latest-scans-panel {
                    /* push panel higher and reduce max height */
                    bottom: calc(40px + var(--footer-height));
                    --latest-scans-max-height: 44vh; /* smaller visible area on narrow phones */
                }
                .latest-scans-panel .list {
                    gap: 6px;
                    padding: 6px 4px;
                }
                .latest-scans-item { padding: 8px; font-size: 0.92rem; }
            }
        </style>

        <div id="latestScansPanel" class="latest-scans-panel" role="region" aria-label="Latest scans" aria-live="polite" aria-atomic="true" style="display:none;">
            <div class="latest-scans-header"><span class="icon">📍</span><span>ការស្កេនចុងក្រោយ</span></div>
            <div class="list" id="latestScansList"></div>
        </div>

        <div class="footer-nav" role="menu" aria-label="Main footer actions">
            <?php if (get_setting_typed('show_home_footer', '1') == '1'): ?>
            <a role="menuitem" class="footer-btn active" data-view="card-menu-view" onclick="footerNavigate(this, 'card-menu-view')" aria-label="ទំព័រដើម">
                <i class="fas fa-home" aria-hidden="true"></i>
                <span>ទំព័រដើម</span>
            </a>
            <?php endif; ?>

            <!-- Central Manual Attendance Button -->
            <?php if (is_manual_scan_allowed()): ?>
            <a role="menuitem" class="footer-btn manual-attendance-btn" onclick="startManualAttendanceProcess()" aria-label="វត្តមានដោយដៃ">

                <i class="fas fa-hand-pointer" aria-hidden="true"></i>
                <span>វត្តមានដោយដៃ</span>
            </a>
            <?php endif; ?>

            <?php if (get_setting_typed('show_my_requests_card', '1') == '1'): ?>
            <a role="menuitem" class="footer-btn" data-view="my-requests-view" onclick="footerNavigate(this, 'my-requests-view')" aria-label="សំណើរបស់ខ្ញុំ">
                <i class="fas fa-clock-rotate-left" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars(get_setting_typed('label_my_requests', 'My Requests')); ?></span>
            </a>
            <?php endif; ?>

            <?php if (get_setting_typed('show_view_logs_card', '1') == '1'): ?>
            <a role="menuitem" class="footer-btn" data-view="my-logs-view" onclick="footerNavigate(this, 'my-logs-view')" aria-label="កំណត់ត្រា">
                <i class="fas fa-clipboard-list" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars(get_setting_typed('label_view_logs', 'View Logs')); ?></span>
            </a>
            <?php endif; ?>

            <?php if (get_setting_typed('show_request_form_card', '1') == '1'): ?>
            <a role="menuitem" class="footer-btn" data-view="request-form-view" onclick="footerNavigate(this, 'request-form-view')" aria-label="ស្នើសុំថ្មី">
                <i class="fa-solid fa-list-check"></i>
                <span><?php echo htmlspecialchars(get_setting_typed('label_request_form', 'Request Form')); ?></span>
            </a>
            <?php endif; ?>

            <?php if (get_setting_typed('show_profile_footer', '1') == '1'): ?>
            <a role="menuitem" class="footer-btn" onclick="toggleProfileSidebar()" aria-label="ប្រវត្តិរូប">
                <i class="fas fa-user" aria-hidden="true"></i>
                <span><?php echo htmlspecialchars(get_setting_typed('label_profile', 'ប្រវត្តិរូប')); ?></span>
            </a>
            <?php endif; ?>
        </div>
        <script>
        // Dynamically add size class (is-1 / is-2) to footer-nav for centering when few items
        (function(){
            const nav = document.querySelector('.app-footer .footer-nav');
            if(!nav) return;
            // Exclude the central manual attendance button from layout calculations
            const visible = Array.from(nav.querySelectorAll('.footer-btn:not(.manual-attendance-btn)')).filter(b => b.offsetParent !== null);
            nav.classList.remove('is-1','is-2','is-3');
            if (visible.length === 1) nav.classList.add('is-1');
            else if (visible.length === 2) nav.classList.add('is-2');
            else if (visible.length === 3) nav.classList.add('is-3');
        })();
        </script>
    </footer>
    <?php endif; ?>

    <!-- ========== AI-ASSISTED QR SCANNER POPUP ========== -->
    <style>
    /* AI Scanner Overlay Styles */
    #aiScannerOverlay {
        position: absolute;
        top: 0; left: 0; right: 0;
        padding: 12px 14px 8px;
        z-index: 10;
        display: flex;
        flex-direction: column;
        gap: 8px;
        pointer-events: none;
    }
    .ai-scanner-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        gap: 8px;
    }
    .ai-badge {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: linear-gradient(135deg, rgba(0,122,255,0.92), rgba(90,50,255,0.88));
        color: #fff;
        font-size: 0.72rem;
        font-weight: 700;
        padding: 4px 10px;
        border-radius: 20px;
        letter-spacing: 0.5px;
        box-shadow: 0 4px 12px rgba(0,122,255,0.35);
        border: 1px solid rgba(255,255,255,0.25);
        pointer-events: auto;
    }
    .ai-badge .ai-dot {
        width: 6px; height: 6px;
        border-radius: 50%;
        background: #4ade80;
        animation: aiPulse 1.2s ease-in-out infinite;
    }
    @keyframes aiPulse {
        0%,100%{ opacity:1; transform: scale(1); }
        50%{ opacity:0.5; transform: scale(0.7); }
    }
    /* GPS Accuracy Bar */
    .gps-accuracy-chip {
        display: inline-flex;
        align-items: center;
        gap: 5px;
        background: rgba(0,0,0,0.55);
        backdrop-filter: blur(8px);
        color: #fff;
        font-size: 0.7rem;
        font-weight: 600;
        padding: 4px 10px;
        border-radius: 20px;
        border: 1px solid rgba(255,255,255,0.18);
        pointer-events: auto;
    }
    .gps-dot { width: 8px; height: 8px; border-radius: 50%; background: #6b7280; flex-shrink:0; }
    .gps-dot.gps-good { background: #4ade80; box-shadow: 0 0 6px rgba(74,222,128,0.6); }
    .gps-dot.gps-warn { background: #fbbf24; box-shadow: 0 0 6px rgba(251,191,36,0.6); }
    .gps-dot.gps-bad  { background: #f87171; box-shadow: 0 0 6px rgba(248,113,113,0.6); }
    .gps-dot.gps-spin {
        background: transparent;
        border: 2px solid rgba(255,255,255,0.4);
        border-top-color: #60a5fa;
        animation: spin 0.8s linear infinite;
    }
    @keyframes spin { to{ transform: rotate(360deg); } }

    /* AI Status Bar below scanner */
    #aiStatusBar {
        position: absolute;
        bottom: 0;
        left: 0; right: 0;
        padding: 10px 14px 6px;
        display: flex;
        flex-direction: column;
        gap: 6px;
        pointer-events: none;
        z-index: 10;
    }
    .ai-status-msg {
        text-align: center;
        font-size: 0.82rem;
        font-weight: 600;
        color: #fff;
        text-shadow: 0 1px 4px rgba(0,0,0,0.6);
        min-height: 18px;
    }
    .ai-tips-row {
        display: flex;
        gap: 6px;
        flex-wrap: wrap;
        justify-content: center;
    }
    .ai-tip-chip {
        display: inline-flex;
        align-items: center;
        gap: 4px;
        background: rgba(0,0,0,0.48);
        backdrop-filter: blur(6px);
        color: rgba(255,255,255,0.88);
        font-size: 0.68rem;
        padding: 3px 8px;
        border-radius: 12px;
        border: 1px solid rgba(255,255,255,0.12);
    }
    /* Smart scanner frame animation */
    .scanner-frame.ai-detecting .corner {
        border-color: #60a5fa !important;
        box-shadow: 0 0 12px rgba(96,165,250,0.5);
    }
    .scanner-frame.ai-success .corner {
        border-color: #4ade80 !important;
        box-shadow: 0 0 18px rgba(74,222,128,0.7) !important;
        animation: successPulse 0.5s ease;
    }
    @keyframes successPulse {
        0%{ transform: scale(1); } 50%{ transform: scale(1.04); } 100%{ transform: scale(1); }
    }
    /* Distance Meter */
    .distance-meter {
        display: flex;
        align-items: center;
        gap: 8px;
        background: rgba(0,0,0,0.52);
        backdrop-filter: blur(8px);
        border: 1px solid rgba(255,255,255,0.14);
        border-radius: 14px;
        padding: 7px 12px;
        pointer-events: auto;
    }
    .distance-meter .dm-icon { font-size: 1rem; }
    .distance-meter .dm-label { font-size: 0.7rem; color: rgba(255,255,255,0.7); }
    .distance-meter .dm-value { font-size: 0.85rem; font-weight: 700; color: #fff; }
    .distance-meter .dm-bar-wrap {
        flex: 1;
        height: 4px;
        background: rgba(255,255,255,0.15);
        border-radius: 4px;
        overflow: hidden;
    }
    .distance-meter .dm-bar {
        height: 100%;
        border-radius: 4px;
        transition: width 0.4s ease, background 0.4s ease;
        background: linear-gradient(90deg, #4ade80, #22c55e);
    }
    /* Action select inside popup */
    .ai-action-row {
        display: flex;
        justify-content: center;
        align-items: center;
        gap: 10px;
        pointer-events: auto;
    }
    </style>

    <div id="cameraPopup" class="popup-overlay">
        <div class="popup-content camera-popup-content" style="padding:0; overflow:hidden; display:flex; flex-direction:column;">

            <!-- Close Button -->
            <a role="button" onclick="stopCamera()" class="close-scanner-btn" aria-label="Close Scanner" style="z-index:20;"><i class="fa-solid fa-xmark"></i></a>

            <!-- AI Overlay TOP -->
            <div id="aiScannerOverlay">
                <div class="ai-scanner-header">
                    <div class="ai-badge">
                        <span class="ai-dot"></span>
                        🤖 AI Scanner
                    </div>
                    <div class="gps-accuracy-chip" id="gpsChip">
                        <span class="gps-dot gps-spin" id="gpsDot"></span>
                        <span id="gpsChipText">GPS...</span>
                    </div>
                </div>
                <!-- Submission Loading -->
                <div id="submission-loading" style="display:none; flex-direction:row; align-items:center; justify-content:center; gap:10px; background:rgba(0,0,0,0.6); backdrop-filter:blur(8px); border-radius:12px; padding:8px 14px;">
                    <div class="upload-spinner" style="width:20px;height:20px;border-width:3px;"></div>
                    <p style="margin:0; color:#fff; font-size:0.85rem; font-weight:600;">កំពុងផ្ទៀងផ្ទាត់...</p>
                </div>
            </div>

            <!-- Camera Preview Container -->
            <div id="scanner-container" style="flex:1; position:relative;">
                <div id="camera-preview-container" style="width:100%; height:100%;"><div id="camera-preview"></div></div>
                <div class="scanner-frame" id="aiScannerFrame">
                    <div class="corner top-left"></div><div class="corner top-right"></div>
                    <div class="corner bottom-left"></div><div class="corner bottom-right"></div>
                    <div class="scanner-laser"></div>
                </div>
            </div>

            <!-- AI Status Bar BOTTOM -->
            <div id="aiStatusBar">
                <!-- Status Message -->
                <div class="ai-status-msg" id="status_msg_popup">កំពុងបើកកាមេរ៉ា...</div>

                <!-- Distance Meter (hidden until GPS ready) -->
                <div class="distance-meter" id="distanceMeter" style="display:none;">
                    <span class="dm-icon">📍</span>
                    <div style="flex:1;">
                        <div class="dm-label">ចម្ងាយពីទីតាំង</div>
                        <div class="dm-value" id="dmValue">--</div>
                    </div>
                    <div class="dm-bar-wrap"><div class="dm-bar" id="dmBar" style="width:0%;"></div></div>
                </div>

                <!-- Smart tips row -->
                <div class="ai-tips-row" id="aiTipsRow">
                    <div class="ai-tip-chip"><span>💡</span> ដាក់ QR ឱ្យស្មើ</div>
                    <div class="ai-tip-chip"><span>☀️</span> ពន្លឺគ្រប់គ្រាន់</div>
                    <div class="ai-tip-chip"><span>📏</span> ចម្ងាយ 10-30 cm</div>
                </div>

                <!-- Action Select -->
                <div class="ai-action-row" style="margin-top:4px;">
                    <span id="actionSelectIcon" class="action-select-icon" aria-hidden="true"><i class="fa-solid fa-right-to-bracket"></i></span>
                    <select id="actionSelectInPopup" class="mobile-input" aria-label="Select attendance action">
                        <option value="Check-In" selected>Check-In (ចូល)</option>
                        <option value="Check-Out">Check-Out (ចេញ)</option>
                    </select>
                </div>

                <!-- Manual Scan Fallback -->
                <?php if (is_manual_scan_allowed()): ?>
                <button id="camPopupManualBtn" onclick="stopCamera(); startManualAttendanceProcess();" class="mobile-button" style="margin-top:6px; width:100%; display:none; background: rgba(255,255,255,0.18); backdrop-filter: blur(10px); color: white; border: 1px solid rgba(255,255,255,0.35); font-size:0.85rem;">
                    <i class="fas fa-hand-pointer"></i> ស្កេនដោយដៃ (Manual Scan)
                </button>
                <?php endif; ?>
            </div>
        </div>
    </div>
    <!-- ========== END AI-ASSISTED QR SCANNER POPUP ========== -->

    <!-- Manual Attendance Popup -->
    <div id="manualPopup" class="popup-overlay" style="display: none;">
        <div class="popup-content camera-popup-content">
            <a role="button" onclick="closeManualPopup()" class="close-scanner-btn" aria-label="Close Manual Attendance"><i class="fa-solid fa-xmark"></i></a>
            <div style="text-align: center; padding: 20px;">
                <h3 style="margin-bottom: 20px; color: white ;">វត្តមានដោយដៃ</h3>
                <p id="manual_status_msg" style="min-height:20px; margin:0 0 20px; font-size:0.85rem; font-weight:500;"></p>
                <div class="form-group select-action-container" style="margin-top:6px;">
                    <span id="manualActionSelectIcon" class="action-select-icon" aria-hidden="true"><i class="fa-solid fa-right-to-bracket"></i></span>
                    <select id="manualActionSelect" class="mobile-input" aria-label="Select attendance action">
                        <option value="Check-In" selected>Check-In (ចូល)</option>
                        <option value="Check-Out">Check-Out (ចេញ)</option>
                    </select>
                </div>
                <button id="manualSubmitBtn" class="mobile-button primary-button" style="margin-top: 20px; width: 100%;" onclick="submitManualAttendance()">ចាប់ផ្តើមស្កេន</button>
            </div>
        </div>
    </div>

    <!-- Enhanced styling for actionSelectInPopup inside camera popup -->
    <style>
    /* Camera popup action select modern style */
    #cameraPopup .select-action-container { position: relative; display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 10px; }
    #cameraPopup .action-select-icon {
        width: 48px; height: 48px; border-radius: 14px;
        display:flex; align-items:center; justify-content:center;
        color:#fff; flex: 0 0 auto;
        background: linear-gradient(135deg, rgba(0,170,120,0.95), rgba(0,200,140,0.90));
        box-shadow: 0 8px 22px rgba(0,0,0,0.28), inset 0 1px 0 rgba(255,255,255,0.35);
        backdrop-filter: blur(6px) saturate(140%);
        -webkit-backdrop-filter: blur(6px) saturate(140%);
        transition: background .05s ease, transform .05s ease, box-shadow .05s ease;
    }
    #cameraPopup .action-select-icon i { font-size: 1.2rem; line-height: 1; }
    #cameraPopup #actionSelectInPopup {
        width: clamp(200px, 64%, 280px);
        min-height: 54px; /* avoid vertical clipping for Khmer glyphs */
        padding: 12px 54px 12px 18px; /* vertical padding ensures room for diacritics */
        font-size: 0.95rem;
        font-weight: 600;
        letter-spacing: .2px; /* slightly reduced to prevent overflow */
        line-height: 1.25; /* more headroom for Khmer */
        white-space: nowrap; /* prevent wrapping that can crop inside native select */
        border-radius: 16px;
        border: 2px solid rgba(255,255,255,0.55);
        background: linear-gradient(135deg, rgba(0,122,255,0.92), rgba(0,160,255,0.88));
        color: #fff;
        box-shadow: 0 8px 26px -6px rgba(0,0,0,0.45), inset 0 1px 0 rgba(255,255,255,0.35);
        backdrop-filter: blur(8px) saturate(140%);
        -webkit-backdrop-filter: blur(8px) saturate(140%);
        appearance: none;
        position: relative;
        transition: box-shadow .05s ease, background .05s ease, transform .05s ease;
        /* Inline chevron icon on the right */
        background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><path fill='white' d='M4 6l4 4 4-4z'/></svg>");
        background-repeat: no-repeat;
        background-position: right 14px center;
        background-size: 12px 12px;
    }
    #cameraPopup #actionSelectInPopup:focus { outline: none; b​ox-shadow: 0 0 0 3px rgba(255,255,255,0.75), 0 10px 32px rgba(0,122,255,0.55); }
    #cameraPopup #actionSelectInPopup:hover { box-shadow: 0 12px 38px -6px rgba(0,0,0,0.6); }
    #cameraPopup #actionSelectInPopup[data-action="Check-In"] {
        background: linear-gradient(135deg, rgba(0,170,120,0.95), rgba(0,200,140,0.90));
        border-color: rgba(255,255,255,0.65);
    }
    #cameraPopup #actionSelectInPopup[data-action="Check-Out"] {
        background: linear-gradient(135deg, rgba(255,140,0,0.95), rgba(255,90,0,0.92));
        border-color: rgba(255,255,255,0.75);
    }
    /* Remove old container-level arrow; we now use background-image on select */
    #cameraPopup .select-action-container:after { display: none; }
    /* Options drop-down (native) readable */
    #cameraPopup #actionSelectInPopup option { color: #0a0a0a; background: #fff; font-weight: 500; }
    @media (max-width:420px){
        #cameraPopup .action-select-icon { width: 44px; height: 44px; }
        #cameraPopup #actionSelectInPopup { min-height: 50px; padding: 10px 48px 10px 14px; font-size: .9rem; line-height: 1.25; }
    }
    </style>

    <style>
    /* Manual Popup Styles */
    #manualPopup .select-action-container { position: relative; display: flex; justify-content: center; align-items: center; gap: 10px; margin-top: 10px; }
    #manualPopup .action-select-icon { position: absolute; right: 10px; top: 50%; transform: translateY(-50%); pointer-events: none; background: linear-gradient(135deg, var(--primary-color), var(--primary-color-dark)); color: #fff; border-radius: 8px; display: flex; align-items: center; justify-content: center; width: 36px; height: 36px; box-shadow: 0 4px 12px rgba(0,122,255,0.2); }
    #manualPopup .action-select-icon i { font-size: 1.2rem; line-height: 1; }
    #manualPopup #manualActionSelect { appearance: none; background: #fff; border: 2px solid rgba(0,122,255,0.2); border-radius: 12px; padding: 12px 48px 12px 16px; font-size: 1rem; font-weight: 600; color: var(--text-primary); cursor: pointer; transition: all .12s ease; min-width: 200px; box-shadow: 0 6px 18px rgba(6,24,80,0.06); }
    #manualPopup #manualActionSelect:focus { outline: none; box-shadow: 0 0 0 3px rgba(255,255,255,0.75), 0 10px 32px rgba(0,122,255,0.55); }
    #manualPopup #manualActionSelect:hover { box-shadow: 0 12px 38px -6px rgba(0,0,0,0.6); }
    #manualPopup #manualActionSelect[data-action="Check-In"] { background: linear-gradient(90deg, rgba(34,197,94,0.1), rgba(34,197,94,0.05)); border-color: rgba(34,197,94,0.3); }
    #manualPopup #manualActionSelect[data-action="Check-Out"] { background: linear-gradient(90deg, rgba(239,68,68,0.1), rgba(239,68,68,0.05)); border-color: rgba(239,68,68,0.3); }
    #manualPopup .select-action-container:after { display: none; }
    #manualPopup #manualActionSelect option { color: #0a0a0a; background: #fff; font-weight: 500; }
    @media (max-width:420px){
        #manualPopup .action-select-icon { width: 44px; height: 44px; }
        #manualPopup #manualActionSelect { min-height: 50px; padding: 10px 48px 10px 14px; font-size: .9rem; line-height: 1.25; }
    }
    </style>

    <script>
    // Dynamic data-action attribute to trigger gradient theme
    (function(){
        const sel = document.getElementById('actionSelectInPopup');
        const iconWrap = document.getElementById('actionSelectIcon');
        const iconEl = iconWrap ? iconWrap.querySelector('i') : null;
        if(!sel) return;
        function apply(){
            const v = sel.value;
            sel.setAttribute('data-action', v);
            if (iconWrap) iconWrap.setAttribute('data-action', v);
            if (iconEl){
                if (v === 'Check-Out') iconEl.className = 'fa-solid fa-right-from-bracket';
                else iconEl.className = 'fa-solid fa-right-to-bracket';
            }
        }
        sel.addEventListener('change', apply); apply();
    })();

    // Dynamic data-action for manual select
    (function(){
        const sel = document.getElementById('manualActionSelect');
        const iconWrap = document.getElementById('manualActionSelectIcon');
        const iconEl = iconWrap ? iconWrap.querySelector('i') : null;
        if(!sel) return;
        function apply(){
            const v = sel.value;
            sel.setAttribute('data-action', v);
            if (iconWrap) iconWrap.setAttribute('data-action', v);
            if (iconEl){
                if (v === 'Check-Out') iconEl.className = 'fa-solid fa-right-from-bracket';
                else iconEl.className = 'fa-solid fa-right-to-bracket';
            }
        }
        sel.addEventListener('change', apply); apply();
    })();
    </script>

    <div id="historyPopup" class="result-popup-overlay" style="display: none;">
        <div class="result-popup-content" style="max-width: 400px; padding: 20px;">
            <h3 style="margin-bottom: 15px;">ជ្រើសរើសហត្ថលេខាចាស់</h3>
            <div id="history-content-container">
                <div id="history-loading" style="text-align: center; display: none;">
                    <div class="upload-spinner" style="position: relative; margin: 0 auto 10px; border: 4px solid rgba(0, 122, 255, 0.2); border-left-color: var(--primary-color);"></div>
                    <p>កំពុងទាញយក...</p>
                </div>
                <div id="history-empty" style="text-align: center; display: none;">
                    <i class="fas fa-archive"></i> មិនមានកំណត់ត្រាហត្ថលេខាចាស់ទេ។
                </div>
                <div id="history-grid" class="history-grid">
                    </div>
            </div>
            <button class="popup-close-btn" onclick="closeHistoryPopup()" style="margin-top: 20px;">បិទ</button>
        </div>
    </div>


    <div id="resultPopup" class="result-popup-overlay" style="display: none;">
        <div class="result-popup-content">
            <div class="popup-icon"><i id="resultPopupIcon"></i></div>
            <h3 id="resultPopupTitle"></h3>
            <p id="resultPopupMessage"></p>
            <button class="popup-close-btn" onclick="closeResultPopup()">យល់ព្រម</button>
        </div>
    </div>

    <!-- Late Reason Popup -->
    <div id="lateReasonPopup" class="result-popup-overlay" style="display: none;">
        <div class="result-popup-content" style="max-width:420px;">
            <h3>សូមបញ្ជាក់មូលហេតុ</h3>
            <p style="color:var(--text-secondary);">ការ Check-Out នេះត្រូវបានកំណត់ថា "Late" — សូមបំពេញមូលហេតុ៖</p>
            <textarea id="lateReasonInput" class="mobile-input" rows="4" placeholder="សរសេរមូលហេតុ..." style="width:100%; margin-top:8px;"></textarea>
            <div style="display:flex; gap:10px; margin-top:14px;">
                <button class="mobile-button" onclick="closeLateReasonPopup()">បោះបង់</button>
                <button class="mobile-button primary-button" id="lateReasonConfirmBtn">បញ្ជាក់ និង បញ្ចូន</button>
            </div>
        </div>
    </div>

    <!-- Notifications Popup -->
    <div id="notificationsPopup" class="result-popup-overlay" style="display: none;">
        <div class="result-popup-content" style="max-width: 500px; max-height: 80vh; overflow-y: auto;">
            <h3 style="margin-bottom: 20px;"><i class="fa-solid fa-bell"></i> ការជូនដំណឹង</h3>
            <div id="notificationsContent">
                <div id="notificationsLoading" style="text-align: center; padding: 20px;">
                    <div class="upload-spinner"></div>
                    <p>កំពុងទាញយកការជូនដំណឹង...</p>
                </div>
                <div id="notificationsList" style="display: none;">
                    <!-- Notifications will be loaded here -->
                </div>
                <div id="noNotifications" style="text-align: center; padding: 20px; color: var(--text-secondary); display: none;">
                    <i class="fa-solid fa-bell-slash" style="font-size: 2rem; margin-bottom: 10px;"></i>
                    <p>មិនមានការជូនដំណឹងថ្មីទេ។</p>
                </div>
            </div>
            <button class="popup-close-btn" onclick="closeNotificationsPopup()" style="margin-top: 20px;">បិទ</button>
        </div>
    </div>

<!-- =============================================== -->
<!-- START: NEW SIDEBAR HTML -->
<!-- =============================================== -->
<?php if ($is_logged_in): ?>
<div id="profileSidebarOverlay" class="profile-sidebar-overlay"></div>

<style>
/* Stylish profile sidebar overrides */
.profile-sidebar {
    width: 320px;
    max-width: 90%;
    background: linear-gradient(180deg, #ffffff 0%, #fbfbff 100%);
    border-left: 1px solid rgba(0,0,0,0.06);
    padding: 0;
    font-family: 'Kantumruy Pro', system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
}

.sidebar-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 18px 16px;
    background: linear-gradient(90deg, rgba(0,122,255,0.95), rgba(10,132,255,0.95));
    color: #fff;
    box-shadow: 0 6px 18px rgba(10,132,255,0.12);
}

.sidebar-header h3 {
    margin: 0;
    font-size: 1rem;
    font-weight: 700;
    letter-spacing: 0.2px;
}

.close-sidebar-btn {
    background: rgba(255,255,255,0.12);
    border: none;
    color: #fff;
    width: 36px;
    height: 36px;
    border-radius: 8px;
    font-size: 18px;
    line-height: 1;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
    transition: transform .12s ease, background .12s ease;
}
.close-sidebar-btn:hover { transform: scale(1.03); background: rgba(255,255,255,0.18); }

/* Content */
.sidebar-content {
    padding: 18px;
    color: var(--text-primary);
    overflow-y: auto;
}

/* User info block */
.user-info { text-align: center; margin-bottom: 14px; }
.user-avatar {
    width: 84px;
    height: 84px;
    margin: 0 auto 10px;
    border-radius: 50%;
    background: linear-gradient(135deg,#e6f0ff,#dff0ff 60%, #ffffff 100%);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--primary-color);
    font-size: 44px;
    box-shadow: 0 8px 20px rgba(13,100,255,0.08), inset 0 -6px 18px rgba(255,255,255,0.6);
}
#sidebarUserName {
    margin: 6px 0 2px;
    font-size: 1.05rem;
    font-weight: 700;
}
#sidebarUserId { margin: 0; color: var(--text-secondary); font-size: 0.85rem; }

/* Custom-data list */
.profile-meta {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-top: 14px;
}
.profile-meta .meta-item {
    background: linear-gradient(180deg, #fff, #fbfbff);
    border: 1px solid #eef3ff;
    padding: 10px;
    border-radius: 10px;
    text-align: left;
    font-size: 0.85rem;
    color: var(--text-primary);
    box-shadow: 0 6px 18px rgba(12,80,200,0.03);
}
.meta-item strong { display:block; font-weight:700; margin-bottom:4px; font-size:0.78rem; color: var(--text-secondary); }

/* Theme switcher */
.theme-settings { margin-top: 16px; }
.theme-settings h4 { margin: 0 0 10px; font-size: 0.95rem; color: var(--text-primary); }
.theme-switcher {
    display:flex;
    gap:8px;
    background: linear-gradient(180deg,#f7f9ff,#ffffff);
    padding:6px;
    border-radius:10px;
    border:1px solid #eef3ff;
}
.theme-btn {
    flex:1;
    padding:8px 10px;
    border-radius:8px;
    border: none;
    cursor: pointer;
    font-weight:600;
    font-size:0.88rem;
    display:inline-flex;
    gap:8px;
    align-items:center;
    justify-content:center;
    color:var(--text-secondary);
    background: transparent;
    transition: all .14s ease;
}
.theme-btn i { font-size: 0.95rem; color: #ffb74d; }
.theme-btn.active {
    background: linear-gradient(90deg, var(--primary-color), var(--primary-color-dark));
    color: #fff;
    box-shadow: 0 8px 20px rgba(0,122,255,0.12);
}
.theme-btn:hover { transform: translateY(-2px); }

/* Small utility */
hr { border: none; border-top: 1px solid rgba(0,0,0,0.06); margin: 12px 0; }
</style>

<div id="profileSidebar" class="profile-sidebar" role="dialog" aria-modal="true">
    <div class="sidebar-header">
        <h3>ព័ត៌មានអ្នកប្រើប្រាស់</h3>
        <button class="close-sidebar-btn" onclick="toggleProfileSidebar()" aria-label="Close sidebar">&times;</button>
    </div>

    <div class="sidebar-content">
        <div class="user-info">
            <?php
            // Try common keys for an admin-uploaded avatar (from custom_data or user_data)
            $avatar_keys = ['avatar_path','profile_image','avatar','photo','picture'];
            $avatar_value = null;
            foreach ($avatar_keys as $k) {
            if (!empty($custom_data[$k])) { $avatar_value = $custom_data[$k]; break; }
            if (!empty($user_data[$k]))   { $avatar_value = $user_data[$k]; break; }
            }

            if ($avatar_value) {
            $avatar_value = trim($avatar_value);
            // If it's a base64 data URI, render directly
            if (preg_match('#^data:image/(png|jpe?g|gif);base64,#i', $avatar_value)) {
                echo '<div class="user-avatar"><img src="'.htmlspecialchars($avatar_value, ENT_QUOTES, 'UTF-8').'" alt="User avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;"></div>';
            }
            // If it's an absolute URL or local file path, prefer URL first
            elseif (preg_match('#^https?://#i', $avatar_value)) {
                echo '<div class="user-avatar"><img src="'.htmlspecialchars($avatar_value, ENT_QUOTES, 'UTF-8').'" alt="User avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;"></div>';
            }
            // If it's a local path, check file exists then serve (use relative path as-is)
            elseif (file_exists($avatar_value)) {
                $src = $avatar_value;
                echo '<div class="user-avatar"><img src="'.htmlspecialchars($src, ENT_QUOTES, 'UTF-8').'" alt="User avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;"></div>';
            }
            // Fallback to icon if value not valid
            else {
                echo '<div class="user-avatar"><i class="fas fa-user-circle"></i></div>';
            }
            } else {
            // Default avatar icon
            echo '<div class="user-avatar"><i class="fas fa-user-circle"></i></div>';
            }
            ?>
            <h4 id="sidebarUserName"><?php echo htmlspecialchars($user_data['name'] ?? 'N/A'); ?></h4>
            <p id="sidebarUserId">ID: <?php echo htmlspecialchars($user_data['employee_id'] ?? 'N/A'); ?></p>

            <!-- START: Dynamically display all custom data from the admin panel -->
            <?php
            $meta_items = [];
            if (isset($custom_data) && is_array($custom_data) && !empty($custom_data)) {
            foreach ($custom_data as $key => $value) {
                if ($value === null || $value === '') continue;

                // Skip avatar-related keys to avoid showing the raw path or duplicate image
                if (in_array($key, $avatar_keys, true)) continue;

                $label = htmlspecialchars(ucfirst(str_replace('_', ' ', $key)));
                // Shorten very long values (e.g., long base64 strings) for display
                $display_raw = is_string($value) ? $value : (string)$value;
                $display_value = htmlspecialchars(mb_strlen($display_raw) > 120 ? mb_substr($display_raw, 0, 117) . '...' : $display_raw);
                $meta_items[] = "<div class=\"meta-item\"><strong>{$label}</strong><span>{$display_value}</span></div>";
            }
            }
            if (!empty($meta_items)) {
            echo '<div class="profile-meta">' . implode('', $meta_items) . '</div>';
            } else {
            echo '<p style="margin-top:12px;color:var(--text-secondary);font-size:0.9rem">មិនមានព័ត៌មានបន្ថែម</p>';
            }
            ?>
            <!-- END: Dynamically display all custom data -->
        </div>

        <hr>

        <div class="sidebar-menu" style="margin-top: 20px; display: flex; flex-direction: column; gap: 8px;">
            <button class="sidebar-menu-btn" onclick="footerNavigate(null, 'my-locations-view'); toggleProfileSidebar();" style="display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px; background: #f5f7fb; border: none; border-radius: 12px; color: var(--text-primary); font-weight: 600; cursor: pointer; transition: all 0.2s;">
                <i class="fas fa-map-location-dot" style="color: var(--primary-color); font-size: 1.1em;"></i>
                <span>ទីតាំងដែលបានអនុញ្ញាត</span>
            </button>

            <a href="scan.php?logout=true" class="sidebar-menu-btn" style="display: flex; align-items: center; gap: 12px; width: 100%; padding: 14px; background: #fff5f5; border: none; border-radius: 12px; color: #e74c3c; font-weight: 600; cursor: pointer; text-decoration: none; transition: all 0.2s;">
                <i class="fas fa-sign-out-alt"></i>
                <span>ចាកចេញពីគណនី</span>
            </a>
        </div>

        <div class="theme-settings">
            <h4>ការកំណត់ផ្ទៃ និងការជូនដំណឹង</h4>
            <div class="theme-switcher" role="tablist" aria-label="Theme settings">
                <button id="theme-light-btn" class="theme-btn" onclick="setTheme('light')" aria-pressed="false">
                    <i class="fas fa-sun"></i> Light
                </button>
                <button id="theme-dark-btn" class="theme-btn" onclick="setTheme('dark')" aria-pressed="false">
                    <i class="fas fa-moon"></i> Dark
                </button>
            </div>

            <button class="mobile-button" onclick="showLocalNotification('តេស្តការជូនដំណឹង', 'នេះគឺជាការសាកល្បងការជូនដំណឹងលើទូរសព្ទរបស់លោកអ្នក។')" style="margin-top: 15px; width: 100%; font-size: 0.85rem; padding: 10px;">
                <i class="fa-solid fa-bell"></i> តេស្តការជូនដំណឹង (Test Notification)
            </button>
        </div>
    </div>
</div>
<?php endif; ?>
<!-- =============================================== -->
<!-- END: NEW SIDEBAR HTML -->
<!-- =============================================== -->


<script>
    "use strict";

    // Theme initialization moved to top of head for better performance and to prevent flicker.

    // Expose server-side custom_data to JS so we can populate checkForm hidden inputs reliably
    // Use json_encode with JSON_HEX_* flags and parse on the client to avoid editor/parser errors and XSS issues.
    const SERVER_CUSTOM_DATA = JSON.parse('<?php echo json_encode($custom_data ?? [], JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP); ?>') || {};

    // Populate hidden check form fields (workplace/branch/area/user_location_raw) before submit
    function populateCheckFormFields() {
        try {
            // user_location_raw should come from gpsDataGlobal if available
            if (typeof gpsDataGlobal !== 'undefined' && gpsDataGlobal) {
                const userLocEl = document.getElementById('user_location_raw');
                if (userLocEl) userLocEl.value = gpsDataGlobal;
            }

            // [កូដដែលបានកែសម្រួល] Fill workplace/branch/area from SERVER_CUSTOM_DATA with multiple key fallbacks
            if (typeof SERVER_CUSTOM_DATA !== 'undefined' && SERVER_CUSTOM_DATA) {
                const wp = SERVER_CUSTOM_DATA.workplace ?? SERVER_CUSTOM_DATA.workplace_name ?? SERVER_CUSTOM_DATA.department ?? SERVER_CUSTOM_DATA['នាយកដ្ឋាន'] ?? '';
                const br = SERVER_CUSTOM_DATA.branch ?? SERVER_CUSTOM_DATA.branch_name ?? SERVER_CUSTOM_DATA['សាខា'] ?? '';
                const ar = SERVER_CUSTOM_DATA.area ?? '';

                const wpEl = document.getElementById('workplace');
                if (wpEl) {
                    // Only overwrite if empty or placeholder present to respect PHP-rendered value first.
                    if (!wpEl.value || wpEl.value === 'N/A') wpEl.value = wp || wpEl.value;
                }

                const brEl = document.getElementById('branch');
                if (brEl) {
                    if (!brEl.value || brEl.value === 'N/A') brEl.value = br || brEl.value;
                }

                const areaEl = document.getElementById('area');
                if (areaEl) {
                    if (!areaEl.value || areaEl.value === 'N/A') areaEl.value = ar || areaEl.value;
                }
            }

            // For debugging: log current values so developer can confirm they're present before submit
            try {
                console.debug('populateCheckFormFields:', {
                    workplace: document.getElementById('workplace')?.value,
                    branch: document.getElementById('branch')?.value,
                    area: document.getElementById('area')?.value,
                    user_location_raw: document.getElementById('user_location_raw')?.value
                });
            } catch (e) { /* ignore */ }
    } catch (e) {
            console.warn('populateCheckFormFields failed', e);
        }
    }

    // ===============================================
    // START: INDEXEDDB MANAGEMENT (OFFLINE MODE)
    // ===============================================
    class ActionDB {
        constructor() {
            this.dbName = 'vvc_attendance_offline_db';
            this.version = 1;
            this.db = null;
        }

        async init() {
            if (this.db) return this.db;
            return new Promise((resolve, reject) => {
                const request = indexedDB.open(this.dbName, this.version);
                request.onupgradeneeded = (e) => {
                    const db = e.target.result;
                    if (!db.objectStoreNames.contains('offline_actions')) {
                        db.createObjectStore('offline_actions', { keyPath: 'id', autoIncrement: true });
                    }
                };
                request.onsuccess = (e) => {
                    this.db = e.target.result;
                    resolve(this.db);
                };
                request.onerror = (e) => reject(e.target.error);
            });
        }

        async saveAction(data) {
            await this.init();
            // Capture client-side timestamp at the moment of action
            const now = new Date();
            const log_datetime = now.getFullYear() + '-' +
                                (String(now.getMonth() + 1).padStart(2, '0')) + '-' +
                                (String(now.getDate()).padStart(2, '0')) + ' ' +
                                (String(now.getHours()).padStart(2, '0')) + ':' +
                                (String(now.getMinutes()).padStart(2, '0')) + ':' +
                                (String(now.getSeconds()).padStart(2, '0'));

            data.log_datetime = log_datetime;

            return new Promise((resolve, reject) => {
                const transaction = this.db.transaction(['offline_actions'], 'readwrite');
                const store = transaction.objectStore('offline_actions');
                const request = store.add({
                    data: data,
                    timestamp: log_datetime
                });
                request.onsuccess = () => resolve(true);
                request.onerror = (e) => reject(e.target.error);
            });
        }

        async getAllActions() {
            await this.init();
            return new Promise((resolve, reject) => {
                const transaction = this.db.transaction(['offline_actions'], 'readonly');
                const store = transaction.objectStore('offline_actions');
                const request = store.getAll();
                request.onsuccess = () => resolve(request.result);
                request.onerror = (e) => reject(e.target.error);
            });
        }

        async deleteAction(id) {
            await this.init();
            return new Promise((resolve, reject) => {
                const transaction = this.db.transaction(['offline_actions'], 'readwrite');
                const store = transaction.objectStore('offline_actions');
                const request = store.delete(id);
                request.onsuccess = () => resolve(true);
                request.onerror = (e) => reject(e.target.error);
            });
        }
    }

    const offlineDB = new ActionDB();

    async function syncOfflineActions() {
        if (!navigator.onLine) return;
        const actions = await offlineDB.getAllActions();
        if (actions.length === 0) return;

        console.log(`Syncing ${actions.length} offline actions...`);
        for (const action of actions) {
            try {
                const fd = new FormData();
                for (const key in action.data) {
                    fd.append(key, action.data[key]);
                }
                // Add a flag to indicate it's a synced action
                fd.append('is_offline_sync', '1');

                const response = await fetch(window.location.pathname, {
                    method: 'POST',
                    body: fd,
                    credentials: 'same-origin'
                });

                if (response.ok) {
                    await offlineDB.deleteAction(action.id);
                    console.log(`Synced action ${action.id} successfully.`);
                }
            } catch (error) {
                console.error(`Failed to sync action ${action.id}:`, error);
            }
        }
        updateOfflineUI();
    }

    async function updateOfflineUI() {
        const actions = await offlineDB.getAllActions();
        const offlineBar = document.getElementById('offline-bar');
        if (offlineBar) {
            if (actions.length > 0) {
                offlineBar.innerHTML = `<i class="fas fa-wifi-slash"></i> កំពុងរង់ចាំការបញ្ជូនទិន្នន័យ (${actions.length})`;
                offlineBar.style.display = 'block';
                offlineBar.style.background = 'var(--warning-color)';
            } else if (!navigator.onLine) {
                offlineBar.innerHTML = `<i class="fas fa-wifi-slash"></i> អ្នកកំពុងប្រើ Offline Mode`;
                offlineBar.style.display = 'block';
                offlineBar.style.background = 'var(--error-color)';
            } else {
                offlineBar.style.display = 'none';
            }
        }
    }

    // Initialize sync and UI
    offlineDB.init().then(() => {
        updateOfflineUI();
        window.addEventListener('online', syncOfflineActions);
        setInterval(syncOfflineActions, 30000); // Try sync every 30s as fallback
    });

    // ===============================================
    // END: INDEXEDDB MANAGEMENT (OFFLINE MODE)
    // ===============================================


    const html5QrCode = new Html5Qrcode("camera-preview", {
        formatsToSupport: [ Html5QrcodeSupportedFormats.QR_CODE ],
        experimentalFeatures: {
            useBarCodeDetectorIfSupported: true
        }
    });
    let isScanning = false;
    let gpsDataGlobal = '';
    let currentSignatureTargetInput = '';
    // Performance/caching helpers
    let selectedCameraDeviceId = null; // cache chosen camera id to avoid re-enumeration
    let lastActionCache = { value: null, ts: 0 }; // cache last action for short TTL
    let pendingDecodedPayload = null; // hold a decoded QR until GPS becomes available
    let hasPendingScan = false;
    // Lightweight profiling flags
    let cameraToFirstDecodeTimerRunning = false;
    let decodeToSubmitTimerRunning = false;

    // ===== START: កូដបន្ថែមថ្មីសម្រាប់ Real-time Update =====
    let requestUpdateInterval = null; // អថេរសម្រាប់เก็บตัวកំណត់เวลา (Timer)
    // ===== END: កូដបន្ថែមថ្មីសម្រាប់ Real-time Update =====

    // =========================================================
    // **NEW FUNCTION: Image Compression before Base64 upload**
    // =========================================================
function compressImage(base64, maxWidth = 800, maxHeight = 800, quality = 0.75) {
    return new Promise((resolve, reject) => {
        const img = new Image();
        img.src = base64;

        img.onload = () => {
            let width = img.width;
            let height = img.height;

            // Calculate new dimensions while maintaining aspect ratio
            if (width > height) {
                if (width > maxWidth) {
                    height *= maxWidth / width;
                    width = maxWidth;
                }
            } else {
                if (height > maxHeight) {
                    width *= maxHeight / height;
                    height = maxHeight;
                }
            }

            // Create a canvas element
            const canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;

            // Draw the resized image onto the canvas
            const ctx = canvas.getContext('2d');
            ctx.drawImage(img, 0, 0, width, height);

            // Get the new base64 string from the canvas, using JPEG format for better compression
            // 'image/jpeg' and the quality parameter (0.75 = 75%) are key for size reduction.
            const newBase64 = canvas.toDataURL('image/jpeg', quality);

            resolve(newBase64);
        };

        img.onerror = (error) => {
            reject(error);
        };
    });
}
    // =========================================================

    // NEW: Re-implemented handleSignaturePreview for file upload with GD processing
    async function handleSignaturePreview(event, targetInputName) {
    const input = event.target;
    const wrapper = input.closest('.signature-upload-wrapper');
    if (!wrapper) return;

    const hiddenPathInput = wrapper.querySelector(`input[name="${targetInputName}"]`);
    const previewImg = wrapper.querySelector('.signature-preview-img');
    const placeholder = wrapper.querySelector('.upload-placeholder');
    const spinner = wrapper.querySelector('.upload-spinner');

    if (input.files && input.files[0]) {
        const file = input.files[0];

        // Check file size on client-side before processing
        if (file.size > 10 * 1024 * 1024) { // 10MB limit
            showResultPopup('ទំហំរូបភាពធំពេក! សូមជ្រើសរើសរូបភាពក្រោម 10MB។', false);
            input.value = ''; // Reset file input
            return;
        }

        placeholder.style.display = 'none';
        previewImg.style.display = 'none';
        spinner.style.display = 'block';
        hiddenPathInput.value = '';

        const reader = new FileReader();
        reader.onload = async function (e) {
            let originalBase64 = e.target.result;
            let processedBase64 = originalBase64;

            try {
                // **STEP 1: AUTO-COMPRESS/RESIZE THE IMAGE IN THE BROWSER**
                processedBase64 = await compressImage(originalBase64, 800, 800, 0.75);
                console.log(`Image compressed. Original: ${originalBase64.length} chars, Compressed: ${processedBase64.length} chars`);

            } catch(error) {
                console.error('Compression Error:', error);
            }

            // --- 2. Call PHP with the COMPRESSED image data ---
            const formData = new FormData();
            formData.append('signature_base64', processedBase64); // Use the compressed data
            formData.append('action', 'upload_signature');

            try {
                const response = await fetch('scan.php', {
                    method: 'POST',
                    body: formData
                });

                if (!response.ok) {
                    const errorText = await response.text();
                    let errorMessage = `Server responded with status ${response.status}.`;
                    // Try to parse JSON error from PHP
                    try {
                        const jsonError = JSON.parse(errorText);
                           if (jsonError.message) {
                               errorMessage = jsonError.message;
                           }
                    } catch(e) { /* Not a JSON error, use the status text */ }
                    throw new Error(errorMessage);
                }

                const result = await response.json();

                spinner.style.display = 'none';

                if (result.success && result.filePath) {
                    updateSignaturePreview(result.filePath, hiddenPathInput, previewImg, placeholder, input);
                    // Don't need a success popup here, it's just a step.
                } else {
                    placeholder.style.display = 'flex';
                    showResultPopup(result.message || 'Error processing signature.', false);
                    input.value = '';
                }
            } catch (error) {
                spinner.style.display = 'none';
                placeholder.style.display = 'flex';
                console.error('Upload Error:', error);
                // This is where the 413 error message was showing
                showResultPopup('កំហុសប្រព័ន្ធ: ' + error.message, false);
                input.value = '';
            }
        };

        reader.readAsDataURL(file);
    }
}

    // Function to update signature preview state - KEY FUNCTION FOR FILLING DATA
    function updateSignaturePreview(base64Image, hiddenInput, previewImg, placeholder, fileInput) {
        hiddenInput.value = base64Image;

        previewImg.src = base64Image;
        previewImg.style.display = 'block';
        placeholder.style.display = 'none';

        if (fileInput) fileInput.value = '';
    }

    // NEW: History Popup Functions
    function showHistoryPopup(targetInputName) {
        currentSignatureTargetInput = targetInputName;
        document.getElementById('historyPopup').style.display = 'flex';
        fetchSignatureHistory();
    }

    function closeHistoryPopup() {
        document.getElementById('historyPopup').style.display = 'none';
        currentSignatureTargetInput = '';
    }

    async function fetchSignatureHistory() {
        const loadingEl = document.getElementById('history-loading');
        const emptyEl = document.getElementById('history-empty');
        const gridEl = document.getElementById('history-grid');

        loadingEl.style.display = 'block';
        emptyEl.style.display = 'none';
        gridEl.innerHTML = '';

        const formData = new FormData();
        formData.append('action', 'fetch_signature_history');

        try {
            const response = await fetch('scan.php', { method: 'POST', body: formData });
            const result = await response.json();

            loadingEl.style.display = 'none';

            if (result.success && result.data.length > 0) {
                let html = '';
                result.data.forEach(item => {
                    html += `
                        <div class="history-item" onclick="selectSignatureFromHistory('${item.base64.replace(/'/g, "\\'")}')">
                            <img src="${item.base64}" alt="Signature" title="Click to Select">
                            <div class="history-item-date">${item.date}</div>
                        </div>
                    `;
                });
                gridEl.innerHTML = html;
            } else {
                emptyEl.style.display = 'block';
            }

        } catch (error) {
            loadingEl.style.display = 'none';
            console.error('Error fetching history:', error);
            emptyEl.innerHTML = 'Error loading history.';
            emptyEl.style.display = 'block';
        }
    }

    function selectSignatureFromHistory(base64Image) {
        if (!currentSignatureTargetInput) return;

        const hiddenInput = document.querySelector(`input[name="${currentSignatureTargetInput}"]`);
        if (!hiddenInput) return;

        const wrapper = hiddenInput.closest('.signature-upload-wrapper');
        const previewImg = wrapper.querySelector('.signature-preview-img');
        const placeholder = wrapper.querySelector('.upload-placeholder');
        const fileInput = wrapper.querySelector('.signature-file-input');

        updateSignaturePreview(base64Image, hiddenInput, previewImg, placeholder, fileInput);

        closeHistoryPopup();
    }

    function showView(viewId) {
        document.querySelectorAll('.main-view').forEach(view => view.classList.remove('active'));
        const targetView = document.getElementById(viewId);
        if(targetView) { targetView.classList.add('active'); }
    }

    // ===== START: កូដដែលបានកែសម្រួលសម្រាប់ Real-time Update =====
    /**
     * កែសម្រួល Function នេះដើម្បីគ្រប់គ្រងការ Polling
     * @param {HTMLElement|null} element - The clicked footer button element.
     * @param {string} viewId - The ID of the view to navigate to.
     */
    function showPageLoader() {
        const ov = document.getElementById('viewTransitionOverlay');
        if (!ov) return;
        ov.classList.remove('fadeout');
        ov.style.display = 'flex';
    }

    function hidePageLoader() {
        const ov = document.getElementById('viewTransitionOverlay');
        if (!ov) return;
        ov.classList.add('fadeout');
        setTimeout(() => { ov.style.display = 'none'; ov.classList.remove('fadeout'); }, 150);
    }

    function footerNavigate(element, viewId) {
        showPageLoader();
        // ជំហានទី 1: បញ្ឈប់ការ Polling ចាស់ជានិច្ចពេលប្តូរទំព័រ
        // ដើម្បីការពារកុំឱ្យ App បន្តទាញទិន្នន័យនៅ Background
        if (requestUpdateInterval) {
            clearInterval(requestUpdateInterval);
            requestUpdateInterval = null;
            console.log('Real-time updates stopped.');
        }

        // កូដដើមសម្រាប់ប្តូរ Active Button
        document.querySelectorAll('.footer-btn').forEach(btn => btn.classList.remove('active'));
        if (!element) {
            element = document.querySelector(`.footer-btn[data-view="${viewId}"]`);
        }
        if(element) element.classList.add('active');

        // បង្ហាញ View ដែលបានជ្រើសរើស (បន្ថែម delay តូចសម្រាប់ animation ហើយកុំឲ្យភ្លឺភ្លាត់)
        setTimeout(() => {
            showView(viewId);
        }, 50);

        // ជំហានទី 2: ពិនិត្យប្រសិនបើទំព័រដែលត្រូវទៅគឺ 'my-requests-view'
        if (viewId === 'my-requests-view') {
            console.log('Starting real-time updates for My Requests view...');
            // ដំណើរការ Function ដើម្បីទាញទិន្នន័យភ្លាមៗពេលបើកទំព័រ
            Promise.all([loadRequestLogs(), updateRequestCounts()])
                   .catch(()=>{})
                   .finally(() => hidePageLoader());

            // ជំហានទី 3: ចាប់ផ្តើម Polling (សួរ Server រៀងរាល់ 10 វិនាទី)
            requestUpdateInterval = setInterval(() => {
                console.log('Polling for new request data...');
                // ហៅ Function ដដែលៗដើម្បីធ្វើឱ្យទិន្នន័យថ្មី
                loadRequestLogs();
                updateRequestCounts();
            }, 10000); // 10000 milliseconds = 10 វិនាទី
        } else if (viewId === 'my-logs-view') {
            loadAttendanceLogs();
            setTimeout(hidePageLoader, 100);
        } else if (viewId === 'my-locations-view') {
            loadLocations();
            setTimeout(hidePageLoader, 100);
        } else {
            // សម្រាប់ view ផ្សេងៗ បិទ loader បន្តិចក្រោយបង្ហាញរួច
            setTimeout(hidePageLoader, 100);
        }
    }
    // ===== END: កូដដែលបានកែសម្រួលសម្រាប់ Real-time Update =====

    // ===============================================
    // START: NEW SIDEBAR & THEME FUNCTIONS
    // ===============================================

    /**
     * Toggles the visibility of the user profile sidebar.
     */
    function toggleProfileSidebar() {
        document.getElementById('profileSidebar').classList.toggle('active');
        document.getElementById('profileSidebarOverlay').classList.toggle('active');
    }

    /**
     * Sets the application theme and saves the preference to localStorage.
     * @param {string} theme - The name of the theme to set ('light' or 'dark').
     */
    function setTheme(theme) {
        const lightThemeBtn = document.getElementById('theme-light-btn');
        const darkThemeBtn = document.getElementById('theme-dark-btn');

        document.documentElement.setAttribute('data-theme', theme);
        localStorage.setItem('appTheme', theme);

        // Update active button state in the sidebar
        if (theme === 'dark') {
            darkThemeBtn?.classList.add('active');
            lightThemeBtn?.classList.remove('active');
        } else {
            lightThemeBtn?.classList.add('active');
            darkThemeBtn?.classList.remove('active');
        }
    }

    // ===============================================
    // END: NEW SIDEBAR & THEME FUNCTIONS
    // ===============================================


    document.addEventListener('DOMContentLoaded', function() {

        // --- NEW: Theme initialization logic ---
        const savedTheme = localStorage.getItem('appTheme') || 'light';
        setTheme(savedTheme);
        // Add event listener to the overlay to close the sidebar
        document.getElementById('profileSidebarOverlay')?.addEventListener('click', toggleProfileSidebar);
        // --- END: Theme initialization logic ---

        // Support for deep linking via URL parameters (e.g. scan.php?view=my-logs-view)
        const urlParams = new URLSearchParams(window.location.search);
        const requestedView = urlParams.get('view');



        if (document.getElementById('login-view') && !<?php echo json_encode(isset($is_logged_in) ? $is_logged_in : false); ?>) {
            showView('login-view');
        } else if (requestedView && document.getElementById(requestedView)) {
            // Priority: URL requested view
            footerNavigate(null, requestedView);
        } else if (document.getElementById('card-menu-view')) {
            showView('card-menu-view');

            const homeButton = document.querySelector('.footer-btn[data-view="card-menu-view"]');
            if (homeButton) {
                homeButton.classList.add('active');
            } else {
                // If Home is hidden, activate the first visible footer button
                const firstBtn = document.querySelector('.footer-btn');
                firstBtn?.classList.add('active');
            }
            // Start live-scan polling when the latest-scans panel exists (logged-in pages)
            if (document.getElementById('latestScansPanel')) {
                startLatestScanPolling();
            }
        }

        document.querySelectorAll('.request-form-fields').forEach(form => {
             disableFormFields(form, true);
        });

        // Prime GPS (if permission already granted) and prefetch last action to reduce latency when user starts scanning
        try {
            // Prefetch last action into cache (non-blocking)
            getLastActionCached().catch(()=>{});
            // Warm GPS if allowed without prompting
            if (navigator.permissions && navigator.permissions.query) {
                navigator.permissions.query({ name: 'geolocation' }).then((res) => {
                    if (res.state === 'granted') {
                        getLocation(() => {});
                    }
                }).catch(()=>{});
            }
        } catch(e) { /* ignore warm-up errors */ }
    });

    function showStatusInPopup(message, isError = false, showLoading = false) {
        const statusEl = document.getElementById('status_msg_popup');
        const loadingEl = document.getElementById('submission-loading');

        if (showLoading) {
            loadingEl.style.display = 'block';
            statusEl.textContent = message;
            statusEl.style.color = 'white';
        } else {
            loadingEl.style.display = 'none';
            statusEl.textContent = message;
            statusEl.style.color = isError ? 'var(--warning-color)' : 'white';
        }
    }

    function disableFormFields(formElement, shouldDisable) {
        formElement.querySelectorAll('input, select, textarea').forEach(field => {
            if (!field.hasAttribute('readonly')) {
                 field.disabled = shouldDisable;
            }
        });
    }

    // Haversine distance calculation in JavaScript
    function haversineDistance(lat1, lon1, lat2, lon2) {
        const R = 6371; // Earth's radius in kilometers
        const dLat = (lat2 - lat1) * Math.PI / 180;
        const dLon = (lon2 - lon1) * Math.PI / 180;
        const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
                  Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
                  Math.sin(dLon / 2) * Math.sin(dLon / 2);
        const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        return R * c * 1000; // Return distance in meters
    }

    // ===== AI SCANNER HELPERS =====
    /**
     * Update the GPS chip UI in the AI scanner overlay
     * @param {'spin'|'good'|'warn'|'bad'} state
     * @param {string} text
     */
    function updateGpsChip(state, text) {
        const dot = document.getElementById('gpsDot');
        const chipText = document.getElementById('gpsChipText');
        if (!dot || !chipText) return;
        dot.className = 'gps-dot gps-' + state;
        chipText.textContent = text;
    }

    /**
     * Update the live distance meter in the AI scanner
     * @param {number|null} distanceM - distance in meters, or null to hide
     * @param {number|null} radiusM - allowed radius in meters
     */
    function updateDistanceMeter(distanceM, radiusM) {
        const meter = document.getElementById('distanceMeter');
        const valEl = document.getElementById('dmValue');
        const barEl = document.getElementById('dmBar');
        if (!meter || !valEl || !barEl) return;
        if (distanceM === null || distanceM === undefined) {
            meter.style.display = 'none';
            return;
        }
        meter.style.display = 'flex';
        const d = Math.round(distanceM);
        valEl.textContent = d >= 1000 ? (d/1000).toFixed(1) + ' km' : d + ' m';
        // Bar: 0% = at location, 100% = at 3x radius (bad)
        const maxDist = radiusM ? radiusM * 3 : 300;
        const pct = Math.min(100, (distanceM / maxDist) * 100);
        // Color: green < radius, yellow < 1.5x, red beyond
        let barColor;
        if (radiusM && distanceM <= radiusM) barColor = 'linear-gradient(90deg, #4ade80, #22c55e)';
        else if (radiusM && distanceM <= radiusM * 1.5) barColor = 'linear-gradient(90deg, #fbbf24, #f59e0b)';
        else barColor = 'linear-gradient(90deg, #f87171, #ef4444)';
        barEl.style.width = pct + '%';
        barEl.style.background = barColor;
    }

    /**
     * Flash the scanner frame with an AI feedback color
     * @param {'detecting'|'success'|'error'} type
     */
    function aiScannerFrameFlash(type) {
        const frame = document.getElementById('aiScannerFrame');
        if (!frame) return;
        frame.classList.remove('ai-detecting','ai-success');
        void frame.offsetWidth; // force reflow
        if (type === 'success') {
            frame.classList.add('ai-success');
            setTimeout(() => frame.classList.remove('ai-success'), 600);
        } else if (type === 'detecting') {
            frame.classList.add('ai-detecting');
        }
    }

    /**
     * Compute live distance from gpsDataGlobal to the nearest known location
     * and update the distance meter in the AI scanner overlay.
     */
    let _distancePollInterval = null;
    function startLiveDistancePolling() {
        if (_distancePollInterval) return; // already running
        async function pollDistance() {
            if (!gpsDataGlobal || gpsDataGlobal.startsWith('Error:')) return;
            try {
                const fd = new FormData();
                fd.append('action', 'fetch_locations');
                const resp = await fetch(window.location.pathname, { method: 'POST', body: fd, credentials: 'same-origin' });
                if (!resp.ok) return;
                const data = await resp.json();
                if (!data.success || !data.data || !data.data.length) return;
                const coords = gpsDataGlobal.split(',').map(parseFloat);
                if (coords.length < 2 || isNaN(coords[0])) return;
                let minDist = Infinity, minRadius = 100, assignedDist = null, assignedRadius = null;
                data.data.forEach(loc => {
                    if (!loc.latitude || !loc.longitude) return;
                    const d = haversineDistance(coords[0], coords[1], parseFloat(loc.latitude), parseFloat(loc.longitude));
                    if (loc.is_assigned == 1) { assignedDist = d; assignedRadius = parseFloat(loc.final_radius) || 100; }
                    if (d < minDist) { minDist = d; minRadius = parseFloat(loc.final_radius) || 100; }
                });
                const useDist = assignedDist !== null ? assignedDist : minDist;
                const useRadius = assignedDist !== null ? assignedRadius : minRadius;
                updateDistanceMeter(useDist, useRadius);
            } catch(e) { /* silent */ }
        }
        pollDistance();
        _distancePollInterval = setInterval(pollDistance, 8000); // 8s: reduce server load
    }

    function stopLiveDistancePolling() {
        if (_distancePollInterval) { clearInterval(_distancePollInterval); _distancePollInterval = null; }
        updateDistanceMeter(null, null);
    }
    // ===== END AI SCANNER HELPERS =====

    function getLocation(callback) {
        showStatusInPopup('កំពុងស្វែងរកទីតាំង GPS...');
        updateGpsChip('spin', 'GPS...');
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                (position) => {
                    gpsDataGlobal = `${position.coords.latitude},${position.coords.longitude}`;
                    const acc = position.coords.accuracy;
                    let gpsState = 'good', gpsText = 'GPS ✓';
                    if (acc <= 20) { gpsState = 'good'; gpsText = 'GPS ±' + Math.round(acc) + 'm'; }
                    else if (acc <= 60) { gpsState = 'warn'; gpsText = 'GPS ±' + Math.round(acc) + 'm'; }
                    else { gpsState = 'warn'; gpsText = 'GPS ±' + Math.round(acc) + 'm'; }
                    updateGpsChip(gpsState, gpsText);
                    startLiveDistancePolling();
                    showStatusInPopup('GPS រួចរាល់!');
                    // If we had a decoded QR waiting for GPS, proceed automatically now
                    try {
                        if (hasPendingScan && pendingDecodedPayload && isScanning) {
                            // Show global loading overlay since camera popup was closed
                            document.getElementById('global-loading-overlay').style.display = 'flex';
                            const payload = pendingDecodedPayload;
                            hasPendingScan = false;
                            pendingDecodedPayload = null;
                            // Proceed without requiring the user to re-scan
                            proceedWithQr(payload).catch(err => {
                                console.error('Pending QR process failed:', err);
                                // Hide loading and show error
                                document.getElementById('global-loading-overlay').style.display = 'none';
                                showResultPopup("កំហុស QR: ទម្រង់ទិន្នន័យមិនត្រឹមត្រូវ! " + (err?.message || err), false);
                                footerNavigate(null, 'card-menu-view');
                            });
                        }
                    } catch(e) { /* ignore */ }
                    callback(true);
                },
                (error) => {
                    gpsDataGlobal = 'Error: GPS_FAIL';
                    let errorMessage = 'GPS បរាជ័យ! សូមពិនិត្យ Permission។';
                    if (error.code === 1) errorMessage = 'សូមអនុញ្ញាតឱ្យ App ប្រើប្រាស់ទីតាំង។';
                    if (error.code === 2) errorMessage = 'រកមិនឃើញសេវា GPS របស់អ្នកទេ។';
                    updateGpsChip('bad', 'GPS ✗');
                    showStatusInPopup(errorMessage, true);
                    callback(false);
                },
                { timeout: 10000, enableHighAccuracy: true, maximumAge: 30000 }
            );
        } else {
            gpsDataGlobal = 'Error: BROWSER_UNSUPPORTED';
            showStatusInPopup('Browser មិនគាំទ្រ GPS ទេ។', true);
            callback(false);
        }
    }

    function startCamera() {
        const config = {
            fps: 50,
            // Full Screen Scanning: Set qrbox to match viewfinder dimensions
            qrbox: function(viewfinderWidth, viewfinderHeight) {
                return { width: viewfinderWidth, height: viewfinderHeight };
            },
            // Removed fixed aspect ratio to allow full screen filling
            experimentalFeatures: {
                useBarCodeDetectorIfSupported: true
            },
            videoConstraints: {
                facingMode: "environment",
                width: { ideal: 1280 },
                height: { ideal: 720 },
                focusMode: "continuous"
            }
        };
        const startScanner = (cameraConfig) => {
             html5QrCode.start(cameraConfig, config, onLocationScanSuccess, (errorMessage) => {
                 // This error callback is for non-critical scan errors, so we can often ignore it.
                 // console.warn('QR scan error:', errorMessage);
                 })
             .catch(err => {
                 showResultPopup("មិនអាចបើក Camera បានទេ។ សូមពិនិត្យ Permission ឬប្រើស្កេនដោយដៃ។", false);
                 // SHOW MANUAL BUTTON IF CAMERA FAILS
                 const manBtn = document.getElementById('camPopupManualBtn');
                 if(manBtn) manBtn.style.display = 'block';

                 // Do not immediately close popup so user sees the button
                 // stopCamera();
                 });
        }
        if (selectedCameraDeviceId) {
            // Fast path: reuse previously selected camera
            startScanner({ deviceId: { exact: selectedCameraDeviceId } });
        } else {
            // Optimized camera selection: prefer back camera, but prioritize speed
            Html5Qrcode.getCameras().then(devices => {
                if (devices && devices.length) {
                    // Quick selection: prefer back camera, fallback to first available
                    let chosen = devices[0].id;
                    for (let device of devices) {
                        if ((device.label || '').toLowerCase().includes('back') ||
                            (device.label || '').toLowerCase().includes('rear')) {
                            chosen = device.id;
                            break;
                        }
                    }
                    selectedCameraDeviceId = chosen;
                    startScanner({ deviceId: { exact: chosen } });
                } else {
                     startScanner({ facingMode: "environment" });
                }
            }).catch(err => {
                 // Fallback for browsers that might not support getCameras well
                 startScanner({ facingMode: "environment" });
            });
        }

        // ================================================================
        // AI BLACK-SCREEN DETECTOR
        // Detects if the camera video feed is black/frozen after startup.
        // If so, automatically switches to manual attendance mode.
        // ================================================================
        aiStartBlackScreenDetector();
    }

    // --- AI Black Screen Detector Implementation ---
    let _blackScreenTimer = null;

    function aiStartBlackScreenDetector() {
        // Clear any previous timer
        if (_blackScreenTimer) { clearTimeout(_blackScreenTimer); _blackScreenTimer = null; }

        // Wait 3s for camera to initialize, then check brightness
        _blackScreenTimer = setTimeout(() => {
            if (!isScanning) return; // Camera already stopped, no need to check
            const brightness = aiSampleVideoBrightness();
            console.log('[AI Camera Check] Average brightness:', brightness);

            if (brightness === null) {
                // Could not sample (no video element yet) — try again in 2s
                _blackScreenTimer = setTimeout(() => {
                    if (!isScanning) return;
                    const b2 = aiSampleVideoBrightness();
                    console.log('[AI Camera Check] Retry brightness:', b2);
                    if (b2 !== null && b2 < 12) {
                        aiHandleBlackScreen();
                    }
                }, 2000);
                return;
            }

            // Threshold: average pixel brightness < 12 out of 255 = essentially black
            if (brightness < 12) {
                aiHandleBlackScreen();
            }
        }, 3000); // Check after 3 seconds
    }

    /**
     * Samples brightness of the active camera video feed.
     * Returns average brightness (0-255), or null if video not available.
     */
    function aiSampleVideoBrightness() {
        try {
            // html5-qrcode renders a <video> inside #camera-preview
            const video = document.querySelector('#camera-preview video');
            if (!video || video.readyState < 2 || video.videoWidth === 0) return null;

            // Sample a small region (64x64) from center for speed
            const canvas = document.createElement('canvas');
            const sampleW = 64, sampleH = 64;
            canvas.width = sampleW;
            canvas.height = sampleH;
            const ctx = canvas.getContext('2d');

            // Draw center of the video frame
            const sx = (video.videoWidth / 2)  - (sampleW / 2);
            const sy = (video.videoHeight / 2) - (sampleH / 2);
            ctx.drawImage(video, sx, sy, sampleW, sampleH, 0, 0, sampleW, sampleH);

            const imgData = ctx.getImageData(0, 0, sampleW, sampleH);
            const pixels = imgData.data; // RGBA flat array
            let total = 0;
            const count = pixels.length / 4;
            for (let i = 0; i < pixels.length; i += 4) {
                // Luminance formula
                total += 0.299 * pixels[i] + 0.587 * pixels[i+1] + 0.114 * pixels[i+2];
            }
            return total / count; // average brightness 0-255
        } catch (e) {
            console.warn('[AI Camera Check] Sample error:', e);
            return null;
        }
    }

    /**
     * Handles confirmed black-screen: stops camera and auto-switches to manual mode.
     */
    function aiHandleBlackScreen() {
        if (!isScanning) return; // Already handled
        console.warn('[AI Camera Check] Black screen detected — switching to manual attendance.');

        // Reset cached camera device so next time it tries fresh
        selectedCameraDeviceId = null;

        // Show AI notification toast before switching
        showAiCameraFallbackToast(() => {
            stopCamera();
            // Small delay so toast is visible briefly
            setTimeout(() => {
                if (typeof startManualAttendanceProcess === 'function') {
                    startManualAttendanceProcess();
                }
            }, 800);
        });
    }

    /**
     * Show a dismissable AI toast explaining the auto-switch to manual.
     * @param {Function} onAutoClose - called when toast auto-hides or is dismissed
     */
    function showAiCameraFallbackToast(onAutoClose) {
        // Remove any existing toast
        const old = document.getElementById('ai-cam-fallback-toast');
        if (old) old.remove();

        const toast = document.createElement('div');
        toast.id = 'ai-cam-fallback-toast';
        toast.style.cssText = `
            position: fixed; bottom: 90px; left: 50%; transform: translateX(-50%);
            z-index: 9999; max-width: 320px; width: 90%;
            background: linear-gradient(135deg, rgba(30,30,50,0.97), rgba(20,20,40,0.97));
            color: #fff; border-radius: 18px;
            padding: 14px 16px; box-shadow: 0 12px 36px rgba(0,0,0,0.45);
            border: 1px solid rgba(96,165,250,0.35);
            backdrop-filter: blur(16px);
            display: flex; gap: 12px; align-items: flex-start;
            animation: toastSlideUp 0.35s cubic-bezier(0.34,1.56,0.64,1) both;
        `;
        toast.innerHTML = `
            <style>
            @keyframes toastSlideUp {
                from { opacity:0; transform: translateX(-50%) translateY(24px) scale(0.95); }
                to   { opacity:1; transform: translateX(-50%) translateY(0)    scale(1); }
            }
            </style>
            <div style="font-size:1.6rem; line-height:1; flex-shrink:0;">🤖</div>
            <div style="flex:1;">
                <div style="font-weight:700; font-size:0.88rem; margin-bottom:4px; color:#93c5fd;">
                    AI បានរកឃើញ Camera ស្រអាប់
                </div>
                <div style="font-size:0.78rem; color:rgba(255,255,255,0.82); line-height:1.5;">
                    Camera បង្ហាញអេក្រង់ខ្មៅ — AI នឹងប្ដូរទៅ <strong style="color:#4ade80;">ស្កេនដោយដៃ</strong> ដោយស្វ័យប្រវត្តិ...
                </div>
            </div>
        `;
        document.body.appendChild(toast);

        // Auto-dismiss and trigger callback after 1.8s
        const dismiss = () => {
            toast.style.transition = 'opacity 0.3s ease, transform 0.3s ease';
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(-50%) translateY(12px)';
            setTimeout(() => { try { toast.remove(); } catch(e){} }, 320);
            if (typeof onAutoClose === 'function') { onAutoClose(); onAutoClose = null; }
        };
        setTimeout(dismiss, 1800);
    }
    // --- END: AI Black Screen Detector ---
    function stopCamera() {
        stopLiveDistancePolling();
        updateGpsChip('spin', 'GPS...');
        if (_blackScreenTimer) { clearTimeout(_blackScreenTimer); _blackScreenTimer = null; } // Clear black screen detector
        if (isScanning && html5QrCode && html5QrCode.isScanning) {
            html5QrCode.stop().then(() => {
                isScanning = false;
                document.getElementById('cameraPopup').style.display = 'none';
                document.getElementById('submission-loading').style.display = 'none'; // Hide loading
                document.getElementById('global-loading-overlay').style.display = 'none'; // Hide global loading
            }).catch(err => {
                // Force close even if stop() fails
                isScanning = false;
                document.getElementById('cameraPopup').style.display = 'none';
                document.getElementById('submission-loading').style.display = 'none'; // Hide loading
                document.getElementById('global-loading-overlay').style.display = 'none'; // Hide global loading
                console.error("Failed to stop camera gracefully:", err);
            });
        } else {
             isScanning = false;
             document.getElementById('cameraPopup').style.display = 'none';
             document.getElementById('submission-loading').style.display = 'none'; // Hide loading
             document.getElementById('global-loading-overlay').style.display = 'none'; // Hide global loading
        }
    }

    // NEW FUNCTION: Auto Selects Check-In/Out based on last action
    function autoSelectAction(lastActionToday) {
        const selectEl = document.getElementById('actionSelectInPopup');
        if (!selectEl) return;

        let nextAction = (lastActionToday === 'Check-In') ? 'Check-Out' : 'Check-In';

        selectEl.value = nextAction;
        console.log(`Auto selected action: ${nextAction} (Last action was ${lastActionToday})`);
    }

    // =======================================================================
    // *** MODIFIED FUNCTION: startAttendanceProcess (OPTIMIZED FOR SPEED) ***
    // =======================================================================
    function startAttendanceProcess() {
        if (isScanning) return;
        isScanning = true;
        gpsDataGlobal = ''; // Reset GPS data
        hasPendingScan = false;
        pendingDecodedPayload = null;

        // --- STEP 1: IMMEDIATE ACTIONS (For better perceived speed) ---
        document.getElementById('cameraPopup').style.display = 'flex';
        document.querySelectorAll('.footer-btn').forEach(btn => btn.classList.remove('active'));
        document.getElementById('submission-loading').style.display = 'none'; // Hide any previous loading
        document.getElementById('global-loading-overlay').style.display = 'none'; // Hide global loading
        showStatusInPopup('កំពុងបើកកាមេរ៉ា...');
        // AI: reset GPS chip and set detecting frame state
        updateGpsChip('spin', 'GPS...');
        aiScannerFrameFlash('detecting');
        updateDistanceMeter(null, null); // hide distance meter until GPS ready
        // Start profiling for camera to first decode
        try { if (!cameraToFirstDecodeTimerRunning) { console.time('camera_to_first_decode'); cameraToFirstDecodeTimerRunning = true; } } catch(e) {}

        // Start the camera right away
        startCamera();

        // --- STEP 2: PARALLEL ACTIONS (Run in the background) ---

        // A. Fetch the last check-in/out action using cache (to avoid extra network if fresh)
        getLastActionCached()
            .then(action => autoSelectAction(action || 'Check-Out'))
            .catch(() => autoSelectAction('Check-Out'));

        // B. Get the user's GPS location
        getLocation(gpsSuccess => {
            if (!gpsSuccess && isScanning) {
                console.warn("GPS failed, but camera is open. User will be warned upon scanning.");
            }
        });
    }

    // =======================================================================
    // *** MODIFIED FUNCTION: onLocationScanSuccess (With GPS Check) ***
    // =======================================================================
    async function onLocationScanSuccess(decodedText, decodedResult) {
        if (!isScanning) return;
        navigator.vibrate?.(100);
        aiScannerFrameFlash('success'); // AI visual feedback: green flash on detect

        // Stop camera-to-first-decode timer
        try { if (cameraToFirstDecodeTimerRunning) { console.timeEnd('camera_to_first_decode'); cameraToFirstDecodeTimerRunning = false; } } catch(e) {}

        // --- CRITICAL CHECK: Wait for GPS data before proceeding ---
        if (!gpsDataGlobal || gpsDataGlobal.startsWith('Error:')) {
            showStatusInPopup('សូមរង់ចាំសញ្ញា GPS...', true);
            // Attempt to get location again, just in case of an initial failure
            hasPendingScan = true;
            pendingDecodedPayload = decodedText;
            getLocation(gpsSuccess => {
                if(gpsSuccess) {
                     showStatusInPopup('GPS រួចរាល់! កំពុងដំណើរការទិន្នន័យ...', false);
                     // The pending flow will proceed from within getLocation on success
                } else {
                     // GPS failed after camera was closed - show global error and hide loading
                     document.getElementById('global-loading-overlay').style.display = 'none';
                     showResultPopup('GPS បរាជ័យ! សូមពិនិត្យ Permission របស់អ្នក។', false);
                     footerNavigate(null, 'card-menu-view');
                }
            });
            return; // IMPORTANT: Stop execution here; will auto-continue after GPS ready
        }

        // --- If GPS is ready, proceed ---
        try { await proceedWithQr(decodedText); } catch(e) {
            // Hide global loading overlay in case of error
            document.getElementById('global-loading-overlay').style.display = 'none';
            stopCamera();
            showResultPopup("កំហុស QR: ទម្រង់ទិន្នន័យមិនត្រឹមត្រូវ! " + (e?.message || e), false);
            footerNavigate(null, 'card-menu-view');
        }
    }

    // Refactored: common path to proceed once QR is decoded and GPS ready
    async function proceedWithQr(decodedText) {
        if (!isScanning) return; // guard
        isScanning = false; // Stop further scans

        // Close camera popup immediately and show global loading
        stopCamera();

        if (!navigator.onLine) {
            // OFFLINE STORAGE LOGIC
            const formDataObj = {};
            const actionType = document.getElementById('actionSelectInPopup').value;

            formDataObj['action'] = actionType;
            formDataObj['qr_location_id'] = qrData.location_id;
            formDataObj['qr_secret'] = qrData.secret;
            formDataObj['user_location_raw'] = gpsDataGlobal;

            // Add other fields if present
            const workplaceEl = document.getElementById('workplace');
            if (workplaceEl) formDataObj['workplace'] = workplaceEl.value;
            const branchEl = document.getElementById('branch');
            if (branchEl) formDataObj['branch'] = branchEl.value;
            const areaEl = document.getElementById('area');
            if (areaEl) formDataObj['area'] = areaEl.value;

            try {
                await offlineDB.saveAction(formDataObj);
                showResultPopup('វត្តមានត្រូវបានរក្សាទុកក្នុងម៉ាស៊ីន (Offline)! វានឹងបញ្ជូនទៅ Server ពេលមានអ៊ីនធឺណិតវិញ។', true);
                updateOfflineUI();
            } catch (err) {
                showResultPopup('កំហុសក្នុងការរក្សាទុកទិន្នន័យ Offline: ' + err.message, false);
            }
            return;
        }

        document.getElementById('global-loading-overlay').style.display = 'flex';

        // Start profiling for decode to submit
        try { if (!decodeToSubmitTimerRunning) { console.time('decode_to_submit'); decodeToSubmitTimerRunning = true; } } catch(e) {}

        const qrData = JSON.parse(decodedText);
        if (!qrData.location_id || !qrData.secret) throw new Error('Invalid QR format');

        document.getElementById('qr_location_id').value = qrData.location_id;
        document.getElementById('qr_secret').value = qrData.secret;
        document.getElementById('user_location_raw').value = gpsDataGlobal;
        document.getElementById('action').value = document.getElementById('actionSelectInPopup').value;

        // If this is a Check-Out, call evaluation endpoint first to determine status
        const actionType = document.getElementById('action').value;
        if (actionType === 'Check-Out') {
            try {
                const evalForm = new FormData();
                evalForm.append('action', 'evaluate_check_status');
                evalForm.append('action_type', actionType);
                evalForm.append('qr_location_id', qrData.location_id);
                evalForm.append('qr_secret', qrData.secret);
                evalForm.append('user_location_raw', gpsDataGlobal);

                const evalResp = await fetch(window.location.pathname, { method: 'POST', body: evalForm, credentials: 'same-origin' });
                if (evalResp.ok) {
                    const evalJson = await evalResp.json();
                    if (evalJson.success && evalJson.data) {
                        const status = evalJson.data.status;
                        if (status === 'Late') {
                            // Show popup to collect late reason, then submit when confirmed.
                            document.getElementById('global-loading-overlay').style.display = 'none';
                            showLateReasonPopup(function(reason) {
                                document.getElementById('late_reason').value = reason || '';
                                try {
                                    let overrideField = document.getElementById('status_override');
                                    if (!overrideField) {
                                        overrideField = document.createElement('input');
                                        overrideField.type = 'hidden';
                                        overrideField.id = 'status_override';
                                        overrideField.name = 'status_override';
                                        document.getElementById('checkForm').appendChild(overrideField);
                                    }
                                    overrideField.value = 'Good';
                                } catch(e) { console.warn('Status override inject failed', e); }
                                try { populateCheckFormFields(); } catch(e){}
                                try { if (decodeToSubmitTimerRunning) { console.timeEnd('decode_to_submit'); decodeToSubmitTimerRunning = false; } } catch(e) {}
                                // Hide global loading before submit
                                document.getElementById('global-loading-overlay').style.display = 'none';
                                setTimeout(() => document.getElementById('checkForm').submit(), 100);
                            });
                            return; // wait for user confirmation
                        }
                    }
                }
            } catch (e) {
                console.error('Evaluation error:', e);
                // fallback: continue to submit
            }
        }

        // Populate workplace/branch/area before submit (use server-provided custom_data if available)
        try { populateCheckFormFields(); } catch(e){}
        try { if (decodeToSubmitTimerRunning) { console.timeEnd('decode_to_submit'); decodeToSubmitTimerRunning = false; } } catch(e) {}
        // Hide global loading before submit
        document.getElementById('global-loading-overlay').style.display = 'none';
        // Submit the form. The page will reload and show the result popup via PHP.
        setTimeout(() => document.getElementById('checkForm').submit(), 100);
    }

    // =======================================================================
    // *** NEW FUNCTION: startManualAttendanceProcess ***
    // =======================================================================
    function startManualAttendanceProcess() {
        gpsDataGlobal = ''; // Reset GPS data
        document.getElementById('manualPopup').style.display = 'flex';
        document.querySelectorAll('.footer-btn').forEach(btn => btn.classList.remove('active'));
        document.getElementById('manual_status_msg').textContent = 'កំពុងរង់ចាំទីតាំង GPS (Optional)...';
        document.getElementById('manualSubmitBtn').disabled = true;
        document.getElementById('manualSubmitBtn').textContent = 'កំពុងរង់ចាំ GPS...';

        // Fetch last action to auto-select
        getLastActionCached()
            .then(action => {
                const selectEl = document.getElementById('manualActionSelect');
                if (selectEl) {
                    let nextAction = (action === 'Check-In') ? 'Check-Out' : 'Check-In';
                    selectEl.value = nextAction;
                }
            })
            .catch(() => {});

        // Get GPS (STRICT for manual attendance)
        getLocation(gpsSuccess => {
            if (gpsSuccess) {
                document.getElementById('manual_status_msg').textContent = 'GPS រកឃើញហើយ។ សូមជ្រើសរើសសកម្មភាព និងចុចស្កេន។';
                document.getElementById('manual_status_msg').style.color = 'var(--success-color)';
                document.getElementById('manualSubmitBtn').disabled = false;
                document.getElementById('manualSubmitBtn').textContent = 'ចាប់ផ្តើមស្កេន';
            } else {
                // GPS not available, strict enforcement requires it
                document.getElementById('manual_status_msg').textContent = 'កំហុស GPS: មិនអាចទាញយកទីតាំងបានទេ។ សូមបើក GPS ដើម្បីបន្ត។';
                document.getElementById('manual_status_msg').style.color = 'var(--error-color)';
                document.getElementById('manualSubmitBtn').disabled = true;
                document.getElementById('manualSubmitBtn').textContent = 'កំហុស GPS';
            }
        });
    }

    function closeManualPopup() {
        document.getElementById('manualPopup').style.display = 'none';
    }

    // =======================================================================
    // *** NEW FUNCTION: submitManualAttendance ***
    // =======================================================================
    async function submitManualAttendance() {
        // For manual attendance, strict location enforcement requires GPS
        const hasGPS = gpsDataGlobal && !gpsDataGlobal.startsWith('Error:');

        if (!hasGPS) {
            alert("កំហុស GPS: មិនអាចទាញយកទីតាំងបច្ចុប្បន្នបានទេ។ សូមបើក GPS ដើម្បីបន្ត។");
            return;
        }

        document.getElementById('manualSubmitBtn').disabled = true;
        document.getElementById('manualSubmitBtn').textContent = 'កំពុងដាក់ស្នើ...';

        if (!navigator.onLine) {
            // OFFLINE STORAGE LOGIC (Manual)
            const formDataObj = {};
            const actionType = document.getElementById('manualActionSelect').value;

            formDataObj['action'] = actionType;
            formDataObj['qr_secret'] = 'manual';
            formDataObj['user_location_raw'] = gpsDataGlobal;
            formDataObj['manual_location_name'] = 'Manual Check (Offline)';

            // Add other fields if present
            const workplaceEl = document.getElementById('workplace');
            if (workplaceEl) formDataObj['workplace'] = workplaceEl.value;
            const branchEl = document.getElementById('branch');
            if (branchEl) formDataObj['branch'] = branchEl.value;
            const areaEl = document.getElementById('area');
            if (areaEl) formDataObj['area'] = areaEl.value;

            try {
                await offlineDB.saveAction(formDataObj);
                showResultPopup('វត្តមានដោយដៃត្រូវបានរក្សាទុកក្នុងម៉ាស៊ីន (Offline)! វានឹងបញ្ជូនទៅ Server ពេលមានអ៊ីនធឺណិតវិញ។', true);
                closeManualPopup();
                updateOfflineUI();
            } catch (err) {
                showResultPopup('កំហុសក្នុងការរក្សាទុកទិន្នន័យ Offline: ' + err.message, false);
            }
            document.getElementById('manualSubmitBtn').disabled = false;
            document.getElementById('manualSubmitBtn').textContent = 'ចាប់ផ្តើមស្កេន';
            return;
        }

        document.getElementById('global-loading-overlay').style.display = 'flex';

        // Automatically determine location based on GPS (STRICT)
        let locationName = 'Manual Check';
        let distanceValue = 0;

        try {
            const formData = new FormData();
            formData.append('action', 'fetch_locations');
            const response = await fetch(window.location.pathname, { method: 'POST', body: formData, credentials: 'same-origin' });
            const data = await response.json();
            if (data.success && data.data && data.data.length > 0) {
                // Find closest location
                const userCoords = gpsDataGlobal.split(',').map(coord => parseFloat(coord.trim()));
                if (userCoords.length === 2 && !isNaN(userCoords[0]) && !isNaN(userCoords[1])) {
                    let closestLocation = null;
                    let minDistance = Infinity;
                    let assignedNearby = null;

                    data.data.forEach(location => {
                        if (location.latitude && location.longitude) {
                            const distance = haversineDistance(userCoords[0], userCoords[1], parseFloat(location.latitude), parseFloat(location.longitude));

                            // Prioritize assigned locations if the user is within their radius
                            if (location.is_assigned == 1 && distance <= parseFloat(location.final_radius)) {
                                if (!assignedNearby || distance < assignedNearby.distance) {
                                    assignedNearby = { ...location, distance: distance };
                                }
                            }

                            if (distance < minDistance) {
                                minDistance = distance;
                                closestLocation = location;
                            }
                        }
                    });

                    // If we found an assigned location that the user is within radius of, prioritize it over a slightly closer unassigned one
                    if (assignedNearby) {
                        closestLocation = assignedNearby;
                        minDistance = assignedNearby.distance;
                    }

                    if (closestLocation) {
                        locationName = closestLocation.location_name;
                        distanceValue = Math.round(minDistance * 100) / 100;

                        // Update Area field in the form to match the detected location
                        const arEl = document.getElementById('area');
                        if (arEl) arEl.value = locationName;

                        // STRICT LOCATION CHECK
                        if (distanceValue > parseFloat(closestLocation.final_radius)) {
                            document.getElementById('global-loading-overlay').style.display = 'none';
                            document.getElementById('manualSubmitBtn').disabled = false;
                            document.getElementById('manualSubmitBtn').textContent = 'ចាប់ផ្តើមស្កេន';
                            alert(`កំហុស Geo: អ្នកនៅឆ្ងាយពីទីតាំងដែលអនុញ្ញាត (${distanceValue}m / Max: ${closestLocation.final_radius}m)។`);
                            return;
                        }
                    } else {
                        document.getElementById('global-loading-overlay').style.display = 'none';
                        document.getElementById('manualSubmitBtn').disabled = false;
                        document.getElementById('manualSubmitBtn').textContent = 'ចាប់ផ្តើមស្កេន';
                        alert("កំហុស៖ មិនអាចស្វែងរកទីតាំងដែលនៅជិតបំផុតបានទេ។");
                        return;
                    }
                }
            } else {
                document.getElementById('global-loading-overlay').style.display = 'none';
                document.getElementById('manualSubmitBtn').disabled = false;
                document.getElementById('manualSubmitBtn').textContent = 'ចាប់ផ្តើមស្កេន';
                alert("កំហុស៖ មិនមានទីតាំងត្រូវបានកំណត់សម្រាប់លោកអ្នកទេ។");
                return;
            }
        } catch (error) {
            console.error('Error determining location:', error);
            // Fallback: server will catch it anyway
        }

        // Set manual values
        document.getElementById('qr_location_id').value = '0'; // Manual location
        document.getElementById('qr_secret').value = 'manual';
        document.getElementById('user_location_raw').value = hasGPS ? gpsDataGlobal : '0,0'; // Default coordinates if no GPS
        document.getElementById('action').value = document.getElementById('manualActionSelect').value;

        // Set manual location name
        let locationNameField = document.getElementById('manual_location_name');
        if (!locationNameField) {
            locationNameField = document.createElement('input');
            locationNameField.type = 'hidden';
            locationNameField.id = 'manual_location_name';
            locationNameField.name = 'manual_location_name';
            document.getElementById('checkForm').appendChild(locationNameField);
        }
        locationNameField.value = locationName;

        // Set distance value
        let distanceField = document.getElementById('manual_distance');
        if (!distanceField) {
            distanceField = document.createElement('input');
            distanceField.type = 'hidden';
            distanceField.id = 'manual_distance';
            distanceField.name = 'manual_distance';
            document.getElementById('checkForm').appendChild(distanceField);
        }
        distanceField.value = distanceValue;

        const actionType = document.getElementById('action').value;

        // If Check-Out, evaluate status
        if (actionType === 'Check-Out') {
            try {
                const evalForm = new FormData();
                evalForm.append('action', 'evaluate_check_status');
                evalForm.append('action_type', actionType);
                evalForm.append('qr_location_id', '0');
                evalForm.append('qr_secret', 'manual');
                evalForm.append('user_location_raw', gpsDataGlobal);

                const evalResp = await fetch(window.location.pathname, { method: 'POST', body: evalForm, credentials: 'same-origin' });
                if (evalResp.ok) {
                    const evalJson = await evalResp.json();
                    if (evalJson.success && evalJson.data) {
                        const status = evalJson.data.status;
                        if (status === 'Late') {
                            document.getElementById('global-loading-overlay').style.display = 'none';
                            showLateReasonPopup(function(reason) {
                                document.getElementById('late_reason').value = reason || '';
                                try {
                                    let overrideField = document.getElementById('status_override');
                                    if (!overrideField) {
                                        overrideField = document.createElement('input');
                                        overrideField.type = 'hidden';
                                        overrideField.id = 'status_override';
                                        overrideField.name = 'status_override';
                                        document.getElementById('checkForm').appendChild(overrideField);
                                    }
                                    overrideField.value = 'Good';
                                } catch(e) { console.warn('Status override inject failed', e); }
                                try { populateCheckFormFields(); } catch(e){}
                                document.getElementById('global-loading-overlay').style.display = 'none';
                                closeManualPopup();
                                setTimeout(() => document.getElementById('checkForm').submit(), 100);
                            });
                            return;
                        }
                    }
                }
            } catch (e) {
                console.error('Evaluation error:', e);
            }
        }

        // Populate and submit
        try { populateCheckFormFields(); } catch(e){}
        document.getElementById('global-loading-overlay').style.display = 'none';
        closeManualPopup();
        setTimeout(() => document.getElementById('checkForm').submit(), 100);
    }

    // Cached fetch for last action with TTL (60s)
    async function getLastActionCached() {
        const now = Date.now();
        const TTL = 60000; // 60 seconds
        try {
            if (lastActionCache.value && (now - lastActionCache.ts) < TTL) {
                return lastActionCache.value;
            }
            const formData = new FormData();
            formData.append('action', 'fetch_last_action');
            const response = await fetch('scan.php', { method: 'POST', body: formData });
            const result = await response.json();
            if (result && result.success) {
                lastActionCache = { value: result.last_action, ts: now };
                return result.last_action;
            }
            // fallback
            return null;
        } catch(e) {
            return null;
        }
    }

    // Late reason popup helpers
    let __lateReasonConfirmHandler = null;
    function showLateReasonPopup(onConfirm) {
        const popup = document.getElementById('lateReasonPopup');
        const input = document.getElementById('lateReasonInput');
        const confirmBtn = document.getElementById('lateReasonConfirmBtn');
        input.value = '';
        popup.style.display = 'flex';
        input.focus();

        // remove any previous handler
        if (__lateReasonConfirmHandler) confirmBtn.removeEventListener('click', __lateReasonConfirmHandler);

        __lateReasonConfirmHandler = function() {
            const reason = input.value.trim();
            closeLateReasonPopup();
            if (typeof onConfirm === 'function') onConfirm(reason);
        };

        confirmBtn.addEventListener('click', __lateReasonConfirmHandler);
    }

    function closeLateReasonPopup() {
        const popup = document.getElementById('lateReasonPopup');
        const confirmBtn = document.getElementById('lateReasonConfirmBtn');
        if (__lateReasonConfirmHandler) {
            confirmBtn.removeEventListener('click', __lateReasonConfirmHandler);
            __lateReasonConfirmHandler = null;
        }
        popup.style.display = 'none';
    }

    document.getElementById('requestType')?.addEventListener('change', function(event) {
        document.querySelectorAll('.request-form-fields').forEach(form => {
             form.style.display = 'none';
             disableFormFields(form, true);
        });

        document.querySelectorAll('.processed-signature-path').forEach(input => { input.value = ''; });
        document.querySelectorAll('.signature-preview-img').forEach(img => { img.style.display = 'none'; img.src = ''; });
        document.querySelectorAll('.upload-placeholder').forEach(ph => { ph.style.display = 'flex'; });
        document.querySelectorAll('.signature-file-input').forEach(input => { input.value = ''; });


        const selectedForm = event.target.value;
        if (selectedForm) {
            const formIdToShow = 'form-' + selectedForm;
            const formToShow = document.getElementById(formIdToShow);
            if (formToShow) {
                 disableFormFields(formToShow, false);
                 formToShow.style.display = 'block';

                 if (selectedForm === 'Forget-Attendance') {
                     document.getElementById('forgetType').dispatchEvent(new Event('change'));
                 }
            }
        }
    });

    document.getElementById('forgetType')?.addEventListener('change', function(event) {
        const selectedType = event.target.value;
        const timeInputsContainer = document.getElementById('time-inputs-container');
        const checkInGroup = document.getElementById('check-in-time-group');
        const checkOutGroup = document.getElementById('check-out-time-group');
        const checkInInput = checkInGroup.querySelector('input');
        const checkOutInput = checkOutGroup.querySelector('input');
        const forgotCountGroup = document.getElementById('forgot-count-group');
        const forgotCountInput = forgotCountGroup.querySelector('input');

        timeInputsContainer.style.display = 'none';
        checkInGroup.style.display = 'none';
        checkOutGroup.style.display = 'none';
        checkInInput.required = false;
        checkOutInput.required = false;
        checkInInput.disabled = true;
        checkOutInput.disabled = true;
        forgotCountGroup.style.display = 'none';
        forgotCountInput.required = false;
        forgotCountInput.disabled = true;

        if (selectedType === 'Check-In') {
            timeInputsContainer.style.display = 'block';
            checkInGroup.style.display = 'block';
            checkInInput.required = true;
            checkInInput.disabled = false;
            forgotCountGroup.style.display = 'block';
            forgotCountInput.required = true;
            forgotCountInput.disabled = false;
        } else if (selectedType === 'Check-Out') {
            timeInputsContainer.style.display = 'block';
            checkOutGroup.style.display = 'block';
            checkOutInput.required = true;
            checkOutInput.disabled = false;
            forgotCountGroup.style.display = 'block';
            forgotCountInput.required = true;
            forgotCountInput.disabled = false;
        } else if (selectedType === 'Both') {
            timeInputsContainer.style.display = 'block';
            checkInGroup.style.display = 'block';
            checkOutGroup.style.display = 'block';
            checkInInput.required = true;
            checkOutInput.required = true;
            checkInInput.disabled = false;
            checkOutInput.disabled = false;
        }
    });

    async function submitRequest(event) {
        event.preventDefault();

        const requestForm = document.getElementById('requestForm');

        const requestType = document.getElementById('requestType').value;
        const formIdToShow = 'form-' + requestType;

        // 1. **SIGNATURE VALIDATION**
        let signatureFieldName = '';
        if(requestType === 'Leave') signatureFieldName = 'signature_path_leave';
        else if(requestType === 'Overtime') signatureFieldName = 'signature_path_overtime';
        else if(requestType === 'Forget-Attendance') signatureFieldName = 'signature_path_forget';
        else if(requestType === 'Late') signatureFieldName = 'signature_path_late';
        else if(requestType === 'Change-Day-Off') signatureFieldName = 'signature_path_cdo';

        const signaturePathInput = document.querySelector(`input[name="${signatureFieldName}"]`);

        // Check the HIDDEN input value (where base64 is stored)
        if (signaturePathInput && !signaturePathInput.value) {
            showResultPopup('សូមបញ្ចូលហត្ថលេខា ឬជ្រើសរើសពីប្រវត្តិ!', false);
            return;
        }

        // 2. Trigger browser's native validation on the rest of the form.
        if (!requestForm.reportValidity()) {
             return;
        }

        const activeFormContainer = document.getElementById(formIdToShow);

        // 3. Collect data only from the active and enabled form fields
        const formData = {};
        requestForm.querySelectorAll('input:not([readonly]), select:not([readonly]), textarea:not([readonly])').forEach(field => {
            if (!field.disabled && field.name) {
                formData[field.name] = field.value;
            }
        });

        // 4. Prepare the AJAX data payload (Sending the full data as JSON for PHP mapping)
        const ajaxData = new FormData();
        ajaxData.append('action', 'submit_request');
        ajaxData.append('requestType', requestType);
        ajaxData.append('formDataJson', JSON.stringify(formData)); // Send full form data to PHP for mapping

        try {
            const submitBtn = event.submitter || document.querySelector('button[form="requestForm"][type="submit"]');

            if (!navigator.onLine) {
                showResultPopup('កំហុស៖ គ្មានប្រព័ន្ធអ៊ីនធឺណិត។ សូមភ្ជាប់អ៊ីនធឺណិតដើម្បីបញ្ជូនទិន្នន័យ។', false);
                return;
            }

            if (submitBtn) {
                submitBtn.disabled = true;
                submitBtn.textContent = 'កំពុងដាក់ស្នើ...';
            }

            const response = await fetch('scan.php', {
                method: 'POST',
                body: ajaxData
            });

            if (!response.ok) {
                 const errorText = await response.text();
                 console.error('Server Error Response Body:', errorText);
                 try {
                     const jsonError = JSON.parse(errorText);
                       if (!jsonError.success && jsonError.message) {
                            throw new Error(jsonError.message);
                        }
                 } catch(e) {
                      throw new Error(`Server responded with status ${response.status}: ${response.statusText}. Check server logs for details.`);
                 }
            }

            const result = await response.json();

            const submitBtnAfter = event.submitter || document.querySelector('button[form="requestForm"][type="submit"]');
            if (submitBtnAfter) {
                submitBtnAfter.disabled = false;
                submitBtnAfter.textContent = 'ដាក់ស្នើ';
            }

            if (result.success) {
                showResultPopup(result.message, true);

                footerNavigate(null, 'card-menu-view');
                document.getElementById('requestForm').reset();

                document.querySelectorAll('.request-form-fields').forEach(form => {
                    form.style.display = 'none';
                    disableFormFields(form, true);
                });
                document.getElementById('time-inputs-container').style.display = 'none';
                document.getElementById('forgot-count-group').style.display = 'none';

                document.querySelectorAll('.processed-signature-path').forEach(input => { input.value = ''; });
                document.querySelectorAll('.signature-preview-img').forEach(img => { img.style.display = 'none'; img.src = ''; });
                document.querySelectorAll('.upload-placeholder').forEach(ph => { ph.style.display = 'flex'; });
                document.querySelectorAll('.signature-file-input').forEach(input => { input.value = ''; });

            } else {
                showResultPopup(result.message || 'កំហុស: ការដាក់ស្នើបរាជ័យ។', false);
            }

        } catch (error) {
            console.error('Submission Error:', error);
            const submitBtn = event.submitter || document.querySelector('button[form="requestForm"][type="submit"]');
            if (submitBtn) {
                submitBtn.disabled = false;
                submitBtn.textContent = 'ដាក់ស្នើ';
            }
            showResultPopup('កំហុសប្រព័ន្ធ: មិនអាចភ្ជាប់ទៅ Server បានទេ។ ឬទម្រង់ទិន្ន្ន័យមានបញ្ហា។ ' + error.message, false);
        }
    }

    // ===== START: កូដបន្ថែមថ្មីសម្រាប់ Real-time Update =====
    /**
     * Function ថ្មីសម្រាប់ទាញយកតែចំនួនសំណើ (Pending, Approved, Rejected)
     * ដើម្បី Update UI ឱ្យស្រាលជាងមុន
     */
    async function updateRequestCounts() {
        const ajaxData = new FormData();
        ajaxData.append('action', 'fetch_request_counts');

        try {
            const response = await fetch('scan.php', { method: 'POST', body: ajaxData });
            const result = await response.json();
            if (result.success) {
                document.getElementById('pending-count').textContent = `${result.data.Pending} សំណើ`;
                document.getElementById('approved-count').textContent = `${result.data.Approved} សំណើ`;
                document.getElementById('rejected-count').textContent = `${result.data.Rejected} សំណើ`;
            }
        } catch (error) {
            console.error('Failed to update request counts:', error);
        }
    }
    // ===== END: កូដបន្ថែមថ្មីសម្រាប់ Real-time Update =====

    // ===== START: REAL-TIME CLIENT CONFIG UPDATE =====
    async function updateClientConfig() {
        const formData = new FormData();
        formData.append('action', 'fetch_client_config');

        try {
            const response = await fetch('scan.php', { method: 'POST', body: formData });
            const result = await response.json();

            if (result.success && result.data) {
                const data = result.data;

                // 1. Update Global Config Variable
                if (typeof SERVER_CUSTOM_DATA !== 'undefined') {
                    // Update in place
                    Object.keys(SERVER_CUSTOM_DATA).forEach(k => delete SERVER_CUSTOM_DATA[k]);
                    Object.assign(SERVER_CUSTOM_DATA, data.custom_data);
                }

                // 2. Toggle Manual Scan Buttons
                const allowed = data.config.manual_scan_allowed;
                const manualFooterBtn = document.querySelector('.manual-attendance-btn');
                const manualPopupBtn = document.getElementById('camPopupManualBtn');

                if (manualFooterBtn) {
                    manualFooterBtn.style.display = allowed ? 'flex' : 'none';
                    // Trigger footer layout recalculation if possible
                    const nav = document.querySelector('.app-footer .footer-nav');
                    if (nav) {
                        const visible = Array.from(nav.querySelectorAll('.footer-btn:not(.manual-attendance-btn)')).filter(b => b.offsetParent !== null);
                        nav.classList.remove('is-1','is-2','is-3');
                        if (visible.length === 1) nav.classList.add('is-1');
                        else if (visible.length === 2) nav.classList.add('is-2');
                        else if (visible.length === 3) nav.classList.add('is-3');
                    }
                }
                if (manualPopupBtn) {
                    // Force style override for popup button to ensure it shows/hides correctly
                    manualPopupBtn.style.cssText = allowed
                        ? "margin-top:15px; width:100%; display:block; background: rgba(255,255,255,0.2); backdrop-filter: blur(10px); color: white; border: 1px solid rgba(255,255,255,0.4);"
                        : "display: none;";
                }

                // 3. Update Profile Sidebar Info
                const sbName = document.getElementById('sidebarUserName');
                const sbId = document.getElementById('sidebarUserId');
                if (sbName) sbName.textContent = data.user_data.name;
                if (sbId) sbId.textContent = 'ID: ' + data.user_data.employee_id;

                const metaContainer = document.querySelector('.profile-meta');
                if (metaContainer) {
                    let metaHTML = '';
                    const avatarKeys = ['avatar_path','profile_image','avatar','photo','picture'];

                    if (data.custom_data && Object.keys(data.custom_data).length > 0) {
                        for (const [key, value] of Object.entries(data.custom_data)) {
                            if (value === null || value === '') continue;
                            if (avatarKeys.includes(key)) continue;

                            let label = key.replace(/_/g, ' ');
                            label = label.charAt(0).toUpperCase() + label.slice(1);

                            let displayVal = String(value);
                            if (displayVal.length > 120) displayVal = displayVal.substring(0, 117) + '...';

                            const safeLabel = label.replace(/[&<>"']/g, function(m){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#039;'}[m] });
                            const safeVal = displayVal.replace(/[&<>"']/g, function(m){ return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;','\'':'&#039;'}[m] });

                            metaHTML += `<div class="meta-item"><strong>${safeLabel}</strong><span>${safeVal}</span></div>`;
                        }
                    }

                    if (metaHTML) {
                        metaContainer.innerHTML = metaHTML;
                    } else {
                        metaContainer.innerHTML = '<p style="margin-top:12px;color:var(--text-secondary);font-size:0.9rem">មិនមានព័ត៌មានបន្ថែម</p>';
                    }
                }
            }
        } catch (error) {
            console.error('Failed to update client config:', error);
        }
    }

    // ===== CLIENT CONFIG POLLING (with storable interval) =====
    let _clientConfigInterval = null;
    function startClientConfigPolling() {
        if (_clientConfigInterval) return; // prevent double-start
        updateClientConfig(); // run immediately
        _clientConfigInterval = setInterval(updateClientConfig, 30000); // 30s: config rarely changes
    }
    function stopClientConfigPolling() {
        if (_clientConfigInterval) { clearInterval(_clientConfigInterval); _clientConfigInterval = null; }
    }
    // ===== END: REAL-TIME CLIENT CONFIG UPDATE ====

    async function loadRequestLogs() {
        const loadingEl = document.getElementById('request-list-loading');
        const emptyEl = document.getElementById('request-list-empty');
        const tableEl = document.getElementById('request-logs-table');

        loadingEl.style.display = 'block';
        emptyEl.style.display = 'none';
        tableEl.style.display = 'none';
        // tableEl.innerHTML = '';  // យើងមិនលុបភ្លាមៗទេ ដើម្បីកុំឱ្យ UI លោតពេលកំពុង update

        const ajaxData = new FormData();
        ajaxData.append('action', 'fetch_requests');

        try {
            const response = await fetch('scan.php', {
                method: 'POST',
                body: ajaxData
            });

            if (!response.ok) {
                 const errorText = await response.text();
                 console.error('Server Error Response Body:', errorText);
                 try {
                     const jsonError = JSON.parse(errorText);
                       if (!jsonError.success && jsonError.message) {
                            throw new Error(jsonError.message);
                        }
                 } catch(e) {
                      throw new Error(`Server responded with status ${response.status}.`);
                 }
            }

            const result = await response.json();

            loadingEl.style.display = 'none';

            if (result.success && result.data.length > 0) {
                let tableHTML = `
                    <thead>
                        <tr>
                            <th>ប្រភេទ</th>
                            <th>ស្ថានភាព</th>
                            <th>ថ្ងៃដាក់ស្នើ</th>
                        </tr>
                    </thead>
                    <tbody>
                `;



                result.data.forEach(item => {
                    const statusClass = `badge-${item.status.replace(/[^a-zA-Z]/g, '')}`;
                    tableHTML += `
                        <tr>
                            <td>${item.type}</td>
                            <td><span class="status-badge ${statusClass}">${item.status}</span></td>
                            <td>${item.date}</td>
                        </tr>
                    `;
                });

                tableHTML += `</tbody>`;
                tableEl.innerHTML = tableHTML;
                tableEl.style.display = 'table';
            } else {
                tableEl.style.display = 'none';
                emptyEl.style.display = 'block';
            }

        } catch (error) {
            console.error('Error fetching request logs:', error);
            loadingEl.style.display = 'none';
            emptyEl.innerHTML = `<i class="fas fa-exclamation-triangle" style="margin-right: 5px;"></i> ${error.message || 'កំហុសពេលទាញយកទិន្នន័យកំណត់ត្រា។'}`;
            emptyEl.style.display = 'block';
        }
    }

    async function loadAttendanceLogs() {
        const dateInput = document.getElementById('log-selected-date');
        const loadingEl = document.getElementById('logs-list-loading');
        const emptyEl = document.getElementById('logs-list-empty');
        const contentEl = document.getElementById('attendance-logs-content');

        loadingEl.style.display = 'block';
        emptyEl.style.display = 'none';
        contentEl.innerHTML = '';

        const ajaxData = new FormData();
        ajaxData.append('action', 'fetch_attendance_logs');
        ajaxData.append('selected_date', dateInput.value);

        try {
            const response = await fetch('scan.php', { method: 'POST', body: ajaxData });
            const result = await response.json();

            loadingEl.style.display = 'none';

            if (result.success && result.data.length > 0) {
                let html = `
                    <div class="log-table-container" style="overflow-x: auto;">
                        <table class="log-table" style="width: 100%; border-collapse: collapse; min-width: 300px;">
                            <thead>
                                <tr style="background: var(--secondary-color);">
                                    <th style="padding: 12px 10px; text-align: left; font-weight: 600;">ម៉ោង</th>
                                    <th style="padding: 12px 10px; text-align: left; font-weight: 600;">សកម្មភាព</th>
                                    <th style="padding: 12px 10px; text-align: left; font-weight: 600;">ស្ថានភាព</th>
                                </tr>
                            </thead>
                            <tbody>
                `;

                result.data.forEach(log => {
                    const statusClass = `status-${log.status.replace(/[^a-zA-Z]/g, '')}`;
                    html += `
                        <tr style="border-bottom: 1px solid #e5e5ea;">
                            <td style="padding: 12px 10px; font-size: 0.9em;">${log.time}</td>
                            <td style="padding: 12px 10px; font-size: 0.9em;">
                                <div style="font-weight: 500;">${log.action}</div>
                                <div style="font-size: 0.8em; color: var(--text-secondary);">${log.location}</div>
                            </td>
                            <td style="padding: 12px 10px; font-size: 0.9em;">
                                <span class="status-badge ${statusClass}" style="background: ${getStatusBg(log.status)}; color: ${getStatusColor(log.status)}; padding: 4px 8px; border-radius: 12px; font-size: 0.8em; font-weight: 600;">
                                    ${log.status}
                                </span>
                            </td>
                        </tr>
                    `;
                });

                html += `</tbody></table></div>`;
                contentEl.innerHTML = html;
            } else {
                emptyEl.style.display = 'block';
            }
        } catch (error) {
            console.error('Error fetching logs:', error);
            loadingEl.style.display = 'none';
            emptyEl.innerHTML = `<i class="fas fa-exclamation-triangle"></i> error`;
            emptyEl.style.display = 'block';
        }
    }

    async function loadLocations() {
        const loadingEl = document.getElementById('locations-list-loading');
        const emptyEl = document.getElementById('locations-list-empty');
        const contentEl = document.getElementById('locations-list-content');

        loadingEl.style.display = 'block';
        emptyEl.style.display = 'none';
        contentEl.innerHTML = '';

        const ajaxData = new FormData();
        ajaxData.append('action', 'fetch_locations');

        try {
            const response = await fetch('scan.php', { method: 'POST', body: ajaxData });
            const result = await response.json();

            loadingEl.style.display = 'none';

            if (result.success && result.data.length > 0) {
                let html = '<div class="location-list" style="display: flex; flex-direction: column; gap: 12px;">';
                result.data.forEach(loc => {
                    html += `
                        <div class="location-item" style="background: var(--surface-color); padding: 14px; border-radius: 12px; border-left: 4px solid var(--primary-color); box-shadow: 0 2px 8px rgba(0,0,0,0.04); border: 1px solid #f0f0f5; border-left-width: 4px;">
                            <h3 style="margin: 0 0 6px 0; font-size: 1rem; color: var(--primary-color); font-weight: 700;">${escapeHtml(loc.location_name)}</h3>
                            <div style="font-size: 0.85rem; color: var(--text-primary);">
                                <div style="margin-bottom: 2px;"><strong style="color: var(--text-secondary); font-weight: 600;">កាំ (Radius):</strong> ${parseInt(loc.final_radius)} ម៉ែត្រ</div>
                                ${loc.is_assigned == 1 ? '<div style="margin-top: 4px; color: var(--success-color); font-weight: 700;"><i class="fas fa-check-circle" style="font-size: 0.9em;"></i> ជាទីតាំងរបស់អ្នក</div>' : ''}
                            </div>
                        </div>
                    `;
                });
                html += '</div>';
                contentEl.innerHTML = html;
            } else {
                emptyEl.style.display = 'block';
            }
        } catch (error) {
            console.error('Error fetching locations:', error);
            loadingEl.style.display = 'none';
            emptyEl.innerHTML = `<i class="fas fa-exclamation-triangle"></i> error`;
            emptyEl.style.display = 'block';
        }
    }

    function getStatusBg(status) {
        if (status === 'Good') return '#d1e7dd';
        if (status === 'Late') return '#f8d7da';
        if (status === 'Absent') return '#fff3cd';
        return '#e9e9e9';
    }

    function getStatusColor(status) {
        if (status === 'Good') return 'var(--success-color)';
        if (status === 'Late') return 'var(--error-color)';
        if (status === 'Absent') return 'var(--warning-color)';
        return 'var(--text-secondary)';
    }

    function showResultPopup(message, isSuccess) {

        const popup = document.getElementById('resultPopup');
        const icon = document.getElementById('resultPopupIcon');
        const title = document.getElementById('resultPopupTitle');
        const msg = document.getElementById('resultPopupMessage');
        if (isSuccess) {
            icon.className = 'fas fa-circle-check';
            title.textContent = 'ជោគជ័យ';
        } else {
            icon.className = 'fas fa-circle-xmark';
            title.textContent = 'មានបញ្ហា';
        }
        msg.textContent = message;
        popup.style.display = 'flex';
    }

    function closeResultPopup() {
        document.getElementById('resultPopup').style.display = 'none';
    }

    /* ===== START: Live Scan Alert (Toast) ===== */
    let latestScanInterval = null;
    let lastSeenScanId = null;
    // How many latest scans to show in the floating panel (change to 1,2,3...)
    const showLatestCount = 2;

    function createScanToastElement() {
        let el = document.getElementById('scan-toast');
        if (el) return el;
        el = document.createElement('div');
        el.id = 'scan-toast';
        el.setAttribute('role','status');
        el.setAttribute('aria-live','polite');
        el.style.position = 'fixed';
        el.style.right = '12px';
        el.style.top = '12px';
        el.style.zIndex = 2500;
        el.style.minWidth = '220px';
        el.style.maxWidth = '360px';
        el.style.pointerEvents = 'auto';
        document.body.appendChild(el);
        return el;
    }

    function showScanToast(scanData) {
        const container = createScanToastElement();
        const wrapper = document.createElement('div');
        wrapper.style.background = 'linear-gradient(90deg, rgba(255,255,255,0.98), rgba(250,250,252,0.95))';
        wrapper.style.border = '1px solid rgba(0,0,0,0.06)';
        wrapper.style.borderRadius = '12px';
        wrapper.style.padding = '10px 12px';
        wrapper.style.boxShadow = '0 8px 26px rgba(2,24,80,0.08)';
        wrapper.style.marginBottom = '10px';
        wrapper.style.display = 'flex';
        wrapper.style.gap = '10px';
        wrapper.style.alignItems = 'center';

    const icon = document.createElement('div');
    const st = String(scanData.status || '').toLowerCase();
    let iconHtml = '<i class="fas fa-circle-xmark"></i>';
    let iconColor = 'var(--error-color)';
    if (st === 'good') { iconHtml = '<i class="fas fa-circle-check"></i>'; iconColor = 'var(--success-color)'; }
    else if (st === 'late') { iconHtml = '<i class="fas fa-circle-exclamation"></i>'; iconColor = 'var(--warning-color)'; }
    icon.innerHTML = iconHtml;
    icon.style.fontSize = '20px';
    icon.style.color = iconColor;

        const content = document.createElement('div');
        content.style.flex = '1';
        content.innerHTML = `<div style="font-weight:700; color:var(--text-primary);">${escapeHtml(scanData.action_type || 'Scan')}</div>
                             <div style="font-size:0.9rem; color:var(--text-secondary);">${escapeHtml(scanData.location_name || 'ផែនទីមិនអាចប្រើបាន')} • ${escapeHtml(formatDateTime(scanData.log_datetime))}</div>`;

        const closeBtn = document.createElement('button');
        closeBtn.innerHTML = '&times;';
        closeBtn.style.border = 'none';
        closeBtn.style.background = 'transparent';
        closeBtn.style.fontSize = '18px';
        closeBtn.style.cursor = 'pointer';
        closeBtn.onclick = () => wrapper.remove();

        wrapper.appendChild(icon);
        wrapper.appendChild(content);
        wrapper.appendChild(closeBtn);

        container.appendChild(wrapper);

        // Auto remove after 7 seconds
        setTimeout(() => { try { wrapper.remove(); } catch(e){} }, 7000);
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str).replace(/[&<>"]+/g, function (s) {
            return ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[s]);
        });
    }

    function formatDateTime(dt) {
        if (!dt) return '';
        try {
            const d = new Date(dt);
            return d.toLocaleString();
        } catch(e) { return dt; }
    }

    async function checkLatestScan() {
        try {
            const formData = new FormData();
            formData.append('action', 'fetch_latest_scan');
            // Post to the current PHP page so an embedded handler (fetch_latest_scan) is reachable
            const resp = await fetch(window.location.pathname, { method: 'POST', body: formData, credentials: 'same-origin' });
            if (!resp.ok) return;
            const json = await resp.json();
            console.debug('fetch_latest_scan response:', json);
            if (!json.success || !Array.isArray(json.data) || json.data.length === 0) return;
            const rows = json.data; // newest-first
            // If this is the first poll, seed lastSeenScanId and populate panel
            if (lastSeenScanId === null) {
                lastSeenScanId = rows[0].id;
                // Populate panel with up to `showLatestCount` newest rows.
                // rows is newest-first, so add from oldest->newest among that slice
                const count = Math.min(showLatestCount, rows.length);
                for (let i = count - 1; i >= 0; i--) {
                    addLatestScanItem(rows[i]);
                }
                return;
            }

            // If newest id differs, find new items and show toast for each (from oldest to newest)
            if (parseInt(rows[0].id) !== parseInt(lastSeenScanId)) {
                // Find items that are newer than lastSeenScanId
                const newItems = [];
                for (let i = rows.length - 1; i >= 0; i--) {
                    const id = parseInt(rows[i].id);
                    if (id > parseInt(lastSeenScanId)) newItems.push(rows[i]);
                }
                // Update lastSeenScanId to newest
                lastSeenScanId = rows[0].id;
                // Show toast for each new item (in chronological order)
                newItems.forEach(item => {
                    showScanToast(item);
                    addLatestScanItem(item);
                });
            }
        } catch (error) {
            // silent fail, will retry next interval
            console.error('Latest scan poll error:', error);
        }
    }

    function startLatestScanPolling() {
        if (latestScanInterval) return;
        checkLatestScan();
        latestScanInterval = setInterval(checkLatestScan, 10000); // Increased to 10 seconds to reduce load
        console.log('Started latest-scan polling');
    }

        function addLatestScanItem(scanData) {
        try {
            const panel = document.getElementById('latestScansPanel');
            const list = document.getElementById('latestScansList');
            if (!panel || !list) return;
            panel.style.display = 'block';

            const item = document.createElement('div');
            item.className = 'latest-scans-item';
                        const st = String(scanData.status || '').toLowerCase();
                        let iconClass = 'fa-circle-xmark';
                        let colorVar = 'var(--error-color)';
                        if (st === 'good') { iconClass = 'fa-circle-check'; colorVar = 'var(--success-color)'; }
                        else if (st === 'late') { iconClass = 'fa-circle-exclamation'; colorVar = 'var(--warning-color)'; }
                        item.innerHTML = `<div style="width:36px; height:36px; border-radius:50%; display:flex; align-items:center; justify-content:center; background:linear-gradient(180deg, #fff, #f5f7fb); box-shadow: 0 6px 18px rgba(6,24,80,0.06); color:${colorVar};"><i class="fas ${iconClass}"></i></div>
                              <div style="flex:1;">
                                <div class="title">${escapeHtml(scanData.action_type || 'Scan')}</div>
                                <div class="meta">${escapeHtml(scanData.location_name || '')} • ${escapeHtml(formatDateTime(scanData.log_datetime))}</div>
                              </div>`;

            // Insert at top
            list.insertBefore(item, list.firstChild);

            // Keep only the configured number of latest items
            while (list.children.length > showLatestCount) list.removeChild(list.lastChild);

            // Auto-hide panel after 20s if empty afterwards
            setTimeout(() => {
                if (list.children.length === 0) panel.style.display = 'none';
            }, 20000);
        } catch (e) { console.error('addLatestScanItem error', e); }
    }

    function stopLatestScanPolling() {
        if (latestScanInterval) { clearInterval(latestScanInterval); latestScanInterval = null; }
    }
    /* ===== END: Live Scan Alert (Toast) ===== */

    /* ===== START: Notifications ===== */
    let currentUnreadCount = 0;
    let currentTotalCount = 0;
    function showNotificationsPopup() {
        const popup = document.getElementById('notificationsPopup');
        popup.style.display = 'flex';
        loadNotifications();
    }

    function closeNotificationsPopup() {
        document.getElementById('notificationsPopup').style.display = 'none';
    }

    function loadNotifications() {
        const loading = document.getElementById('notificationsLoading');
        const list = document.getElementById('notificationsList');
        const noNotifications = document.getElementById('noNotifications');

        loading.style.display = 'block';
        list.style.display = 'none';
        noNotifications.style.display = 'none';

        fetch('', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'ajax_action=get_user_notifications'
        })
        .then(response => response.json())
        .then(data => {
            loading.style.display = 'none';

            if (data.status === 'success' && data.notifications.length > 0) {
                list.innerHTML = '';
                data.notifications.forEach(notification => {
                    const item = document.createElement('div');
                    item.className = `notification-item ${notification.is_read ? 'read' : 'unread'}`;
                    item.style.cssText = `
                        background: white;
                        border: 1px solid #e0e0e0;
                        border-radius: 12px;
                        padding: 16px;
                        margin-bottom: 12px;
                        position: relative;
                        transition: all 0.2s ease;
                        box-shadow: 0 1px 3px rgba(0,0,0,0.1);
                    `;

                    if (!notification.is_read) {
                        item.style.borderLeft = '4px solid #e74c3c';
                        item.style.background = 'linear-gradient(135deg, #fff5f5 0%, white 100%)';
                    } else {
                        item.style.borderLeft = '4px solid #f39c12';
                    }

                    item.innerHTML = `
                        <div style="display: flex; justify-content: space-between; align-items: start;">
                            <div style="flex: 1;">
                                <div style="display: flex; align-items: center; margin-bottom: 8px;">
                                    <h4 style="margin: 0; font-size: 1rem; color: #333; font-weight: 600; flex: 1;">${escapeHtml(notification.title)}</h4>
                                    ${!notification.is_read ? '<span class="unread-indicator" style="width: 8px; height: 8px; background: #e74c3c; border-radius: 50%; margin-left: 8px; flex-shrink: 0;"></span>' : '<span class="read-indicator" style="width: 8px; height: 8px; background: #f39c12; border-radius: 50%; margin-left: 8px; flex-shrink: 0;"></span>'}
                                </div>
                                <p style="margin: 0 0 12px 0; color: #666; font-size: 0.9rem; line-height: 1.4;">${escapeHtml(notification.message)}</p>
                                <small style="color: #999; font-size: 0.8rem;">${escapeHtml(notification.sent_at)}</small>
                            </div>
                            ${!notification.is_read ? '<button onclick="markAsRead(' + notification.id + ', this)" class="mark-read-btn" style="background: #e74c3c; color: white; border: none; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 0.8rem; font-weight: 500; margin-left: 12px; flex-shrink: 0;">អានរួច</button>' : ''}
                        </div>
                    `;
                    list.appendChild(item);
                });
                list.style.display = 'block';
            } else {
                noNotifications.style.display = 'block';
            }

            // Update notification badge
            currentUnreadCount = data.unread_count || 0;
            currentTotalCount = data.total_count || 0;
            updateNotificationBadge(currentUnreadCount, currentTotalCount);
        })
        .catch(error => {
            console.error('Error loading notifications:', error);
            loading.style.display = 'none';
            noNotifications.style.display = 'block';
        });
    }

    function updateNotificationBadge(unreadCount, totalCount) {
        const badge = document.getElementById('notificationBadge');
        if (totalCount > 0) {
            badge.textContent = totalCount > 99 ? '99+' : totalCount;
            badge.style.display = 'flex';
            if (unreadCount > 0) {
                badge.classList.remove('read');
            } else {
                badge.classList.add('read');
            }
        } else {
            badge.style.display = 'none';
        }
    }

    function markAsRead(notificationId, buttonElement) {
        fetch('', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'ajax_action=mark_notification_read&notification_id=' + notificationId
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                // Update the notification item styling
                const item = buttonElement.closest('.notification-item');
                item.className = 'notification-item read';
                item.style.borderLeft = '4px solid #f39c12';
                item.style.background = 'white';

                // Update the indicator
                const indicator = item.querySelector('.unread-indicator');
                if (indicator) {
                    indicator.className = 'read-indicator';
                    indicator.style.background = '#f39c12';
                }

                // Remove the button
                buttonElement.remove();

                // Update badge
                currentUnreadCount = Math.max(0, currentUnreadCount - 1);
                updateNotificationBadge(currentUnreadCount, currentTotalCount);
            }
        })
        .catch(error => {
            console.error('Error marking notification as read:', error);
        });
    }
    /* ===== END: Notifications ===== */

    // Add click event listener for notification button
    document.addEventListener('DOMContentLoaded', function() {
        const notificationBtn = document.querySelector('.notification-btn');
        if (notificationBtn) {
            notificationBtn.addEventListener('click', showNotificationsPopup);
        }

        // Unified polling startup — ONE place, avoid duplicate calls
        // loadNotificationBadge fires via setInterval below (first tick is immediate via flag)
        // startClientConfigPolling already calls updateClientConfig() on first run
        startClientConfigPolling();
    });



    function loadNotificationBadge() {
        fetch('', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: 'ajax_action=get_user_notifications'
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'success') {
                currentUnreadCount = data.unread_count || 0;
                currentTotalCount = data.total_count || 0;
                updateNotificationBadge(currentUnreadCount, currentTotalCount);

                // --- NEW: Handle Real-time Push (Native) Notifications ---
                if (data.notifications && data.notifications.length > 0) {
                    const lastNotifiedId = parseInt(localStorage.getItem('vvc_last_notified_id') || '0');
                    let maxIdSeen = lastNotifiedId;

                    // Sort notifications by ID ascending to notify in order
                    const sorted = [...data.notifications].sort((a,b) => parseInt(a.id) - parseInt(b.id));

                    sorted.forEach(notif => {
                        const notifId = parseInt(notif.id);
                        if (!notif.is_read && notifId > lastNotifiedId) {
                            showLocalNotification(notif.title || 'Notification', notif.message, notifId);
                            if (notifId > maxIdSeen) maxIdSeen = notifId;
                        }
                    });

                    if (maxIdSeen > lastNotifiedId) {
                        localStorage.setItem('vvc_last_notified_id', maxIdSeen);
                    }
                }
            }
        })
        .catch(error => {
            console.error('Error loading notification badge:', error);
        });
    }

    // Notification badge polling — 30s is sufficient; notifications are non-urgent
    // NOTE: setInterval runs immediately on page load via this declaration
    let _notifBadgeInterval = null;
    (function startNotifPolling() {
        loadNotificationBadge(); // first immediate call
        _notifBadgeInterval = setInterval(loadNotificationBadge, 30000); // every 30s
    })();

    window.addEventListener('beforeunload', () => {
        if (isScanning) { stopCamera(); }
        // Clean up all polling intervals gracefully
        stopClientConfigPolling();
        stopLiveDistancePolling();
        if (_notifBadgeInterval) clearInterval(_notifBadgeInterval);
        if (requestUpdateInterval) clearInterval(requestUpdateInterval);
        if (latestScanInterval) clearInterval(latestScanInterval);
    });
</script>

<?php
// Suppress automatic modal popup for time-related scan errors (e.g., missing/invalid check-in/out time)
// so that normal scanning flow isn't interrupted by the modal. We still show popups for other errors/successes.
$suppress_time_error = false;
if (!empty($error_message)) {
    $lower = mb_strtolower($error_message, 'UTF-8');
    if (mb_strpos($lower, 'ម៉ោង') !== false || mb_strpos($lower, 'check-in/out') !== false || mb_strpos($lower, 'check-in') !== false || mb_strpos($lower, 'check-out') !== false) {
        $suppress_time_error = true;
    }
}
if ((!empty($success_message) || !empty($error_message)) && !$suppress_time_error): ?>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const message = <?php echo json_encode(!empty($success_message) ? $success_message : $error_message); ?>;
            const isSuccess = <?php echo !empty($success_message) ? 'true' : 'false'; ?>;
            if (isSuccess) {
                showLocalNotification('ការស្កេនជោគជ័យ', message);
            }
            showResultPopup(message, isSuccess);
        });
    </script>
<?php else: ?>
    <?php if ($suppress_time_error): ?>
    <script>
        // Time-related error suppressed from modal to allow normal scanning flow.
        // For debugging, log the suppressed message to console instead of showing popup.
        document.addEventListener('DOMContentLoaded', function() {
            console.info('Suppressed time-related scan message:', <?php echo json_encode($error_message); ?>);
        });
    </script>
    <?php endif; ?>
<?php endif; ?>


<script>
    // JavaScript សម្រាប់ទប់ស្កាត់ Pinch-to-Zoom (ទប់ស្កាត់การអូសដោយម្រាមដៃពីរ)
    document.addEventListener('gesturestart', function (e) {
        e.preventDefault();
    });

    // សម្រាប់ Browser ចាស់ៗដែលប្រើ touchmove
    document.addEventListener('touchmove', function (event) {
        // ពិនិត្យមើលថាតើមានម្រាមដៃលើសពីមួយនៅលើអេក្រង់ទេ? (Pinch)
        if (event.scale !== 1) {
            event.preventDefault();
        }
    }, { passive: false });
</script>

<?php
// Suppress automatic modal popup for time-related scan errors (e.g., missing/invalid check-in/out time)
// so that normal scanning flow isn't interrupted by the modal. We still show popups for other errors/successes.
$suppress_time_error = false;
if (!empty($error_message)) {
    $lower = mb_strtolower($error_message, 'UTF-8');
    if (mb_strpos($lower, 'ម៉ោង') !== false || mb_strpos($lower, 'check-in/out') !== false || mb_strpos($lower, 'check-in') !== false || mb_strpos($lower, 'check-out') !== false) {
        $suppress_time_error = true;
    }
}
if ((!empty($success_message) || !empty($error_message)) && !$suppress_time_error): ?>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const message = <?php echo json_encode(!empty($success_message) ? $success_message : $error_message); ?>;
            const isSuccess = <?php echo !empty($success_message) ? 'true' : 'false'; ?>;
            showResultPopup(message, isSuccess);
        });
    </script>
<?php else: ?>
    <?php if ($suppress_time_error): ?>
    <script>
        // Time-related error suppressed from modal to allow normal scanning flow.
        // For debugging, log the suppressed message to console instead of showing popup.
        document.addEventListener('DOMContentLoaded', function() {
            console.info('Suppressed time-related scan message:', <?php echo json_encode($error_message); ?>);
        });
    </script>
    <?php endif; ?>
<?php endif; ?>

<script>
    // Register service worker and handle automatic updates
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        // Use a stable URL. updateViaCache: 'none' ensures the script is always fetched from network.
        navigator.serviceWorker.register('sw.js', { updateViaCache: 'none' })
          .then(registration => {
            console.log('ServiceWorker registration successful with scope: ', registration.scope);

            // 1. Manually check for updates on page load
            registration.update();

            // 2. Listen for a new service worker being installed
            registration.onupdatefound = () => {
                const installingWorker = registration.installing;
                if (installingWorker) {
                    installingWorker.onstatechange = () => {
                        if (installingWorker.state === 'installed' && navigator.serviceWorker.controller) {
                            // New version detected. It will auto-activate due to self.skipWaiting() in sw.js
                            console.log('New version available. Processing update...');
                        }
                    };
                }
            };

            // Ask for Notification permission
            if ('Notification' in window) {
              Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                  console.log('Notification permission granted.');
                  // Subscribe user for real Push notifications (works when app is closed)
                  subscribeUserToPush(registration);
                }
              });
            }
          }, err => {
            console.log('ServiceWorker registration failed: ', err);
          });
      });

      // 3. Automatically reload the page when the service worker has updated and taken control
      let refreshing = false;
      navigator.serviceWorker.addEventListener('controllerchange', () => {
        if (!refreshing) {
          refreshing = true;
          console.log('Service worker updated. Reloading page for new content...');
          window.location.reload();
        }
      });
    }

    // --- Web Push Subscription Logic ---
    function urlBase64ToUint8Array(base64String) {
        const padding = '='.repeat((4 - base64String.length % 4) % 4);
        const base64 = (base64String + padding).replace(/\-/g, '+').replace(/_/g, '/');
        const rawData = window.atob(base64);
        const outputArray = new Uint8Array(rawData.length);
        for (let i = 0; i < rawData.length; ++i) {
            outputArray[i] = rawData.charCodeAt(i);
        }
        return outputArray;
    }

    async function subscribeUserToPush(registration) {
        const publicVapidKey = '<?php echo VAPID_PUBLIC_KEY; ?>';
        try {
            const subscription = await registration.pushManager.subscribe({
                userVisibleOnly: true,
                applicationServerKey: urlBase64ToUint8Array(publicVapidKey)
            });

            console.log('User is subscribed to Push:', subscription);

            // Send subscription to server
            await fetch('', {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: 'ajax_action=save_push_subscription&subscription=' + encodeURIComponent(JSON.stringify(subscription))
            });
        } catch (error) {
            console.error('Failed to subscribe user to Push:', error);
        }
    }


    // Function to show a local notification (improved for mobile Reliability)
    function showLocalNotification(title, body, notifId = null) {
        if (!('Notification' in window)) {
            console.warn('Notifications not supported in this browser.');
            return;
        }

        const options = {
            body: body,
            icon: 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png',
            badge: 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png',
            vibrate: [200, 100, 200],
            tag: notifId ? 'notif-' + notifId : 'attendance-notification-' + Date.now(),
            renotify: true,
            requireInteraction: false
        };

        if (Notification.permission === 'granted') {
            if ('serviceWorker' in navigator) {
                navigator.serviceWorker.ready.then(registration => {
                    registration.showNotification(title, options);
                }).catch(err => {
                    console.error('SW Notification failed, trying native:', err);
                    new Notification(title, options);
                });
            } else {
                new Notification(title, options);
            }
        } else if (Notification.permission !== 'denied') {
            Notification.requestPermission().then(permission => {
                if (permission === 'granted') {
                    showLocalNotification(title, body, notifId);
                }
            });
        }
    }

    // JavaScript សម្រាប់ទប់ស្កាត់ Pinch-to-Zoom (ទប់ស្កាត់การអូសដោយម្រាមដៃពីរ)
    document.addEventListener('gesturestart', function (e) {
        e.preventDefault();
    });

    // សម្រាប់ Browser ចាស់ៗដែលប្រើ touchmove
    document.addEventListener('touchmove', function (event) {
        // ពិនិត្យមើលថាតើមានម្រាមដៃលើសពីមួយនៅលើអេក្រង់ទេ? (Pinch)
        if (event.scale !== 1) {
            event.preventDefault();
        }
    }, { passive: false });

    // --- Offline Mode Detection & UI ---
    function updateOnlineStatus() {
        const offlineBar = document.getElementById('offline-bar');
        if (navigator.onLine) {
            offlineBar.style.display = 'none';
        } else {
            offlineBar.style.display = 'block';
            console.warn('App is offline. Using cached UI.');
        }
    }

    window.addEventListener('online', updateOnlineStatus);
    window.addEventListener('offline', updateOnlineStatus);
    document.addEventListener('DOMContentLoaded', updateOnlineStatus);

    // Override fetch to handle offline errors gracefully for essential actions
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        try {
            return await originalFetch(...args);
        } catch (error) {
            if (!navigator.onLine) {
                console.error('Fetch failed because app is offline:', args[0]);
                // Return a fake response that some parts of the app can handle
                if (args[0].includes('fetch_last_action')) {
                    return new Response(JSON.stringify({success: false, message: 'Offline'}), {status: 503});
                }
            }
            throw error;
        }
    };
</script>

</body>
<script>
// ===== Custom PWA Install Flow =====
let deferredPrompt = null;
const installOverlay = document.getElementById('pwa-install-prompt');
const installBtn = document.getElementById('pwaInstallBtn');
const laterBtn = document.getElementById('pwaLaterBtn');
const dismissBtn = document.getElementById('pwaDismissBtn');

// Only show prompt if not installed already
function isStandalone(){
    return (window.matchMedia('(display-mode: standalone)').matches) || (window.navigator.standalone === true);
}

function showInstallPrompt(){
    if (!installOverlay || isStandalone()) return;
    installOverlay.style.display = 'flex';
}

function hideInstallPrompt(){
    if (installOverlay) installOverlay.style.display = 'none';
    // Optionally remember user dismissed (localStorage)
    localStorage.setItem('pwa_install_dismissed','1');
}

window.addEventListener('beforeinstallprompt', (e) => {
    e.preventDefault();
    deferredPrompt = e; // store
    if (localStorage.getItem('pwa_install_dismissed') !== '1') {
        // slight delay to avoid layout shift
        setTimeout(showInstallPrompt, 800);
    }
});

installBtn?.addEventListener('click', async () => {
    if (!deferredPrompt) { hideInstallPrompt(); return; }
    deferredPrompt.prompt();
    const choice = await deferredPrompt.userChoice;
    if (choice.outcome === 'accepted') {
        hideInstallPrompt();
    } else {
        // user dismissed internal browser prompt but keep our overlay hidden for now
        hideInstallPrompt();
    }
    deferredPrompt = null;
});

laterBtn?.addEventListener('click', () => {
    hideInstallPrompt();
    // allow it to show again in a future session (remove dismissal flag)
    setTimeout(()=>localStorage.removeItem('pwa_install_dismissed'), 1000*60*60*6); // 6h
});

dismissBtn?.addEventListener('click', hideInstallPrompt);

// If user navigated later and event already fired earlier (Safari style fallback) offer manual button if any
document.addEventListener('DOMContentLoaded', () => {
    if (!isStandalone() && 'serviceWorker' in navigator) {
        // Fallback manual show if beforeinstallprompt never fires after some time
        setTimeout(()=>{
            if (!deferredPrompt && localStorage.getItem('pwa_install_dismissed')!=='1') {
                // Attempt to guess support (Chrome / Edge / Android). iOS Safari uses different pattern.
                if (/(android|chrome|edg)/i.test(navigator.userAgent)) {
                    showInstallPrompt();
                }
            }
        }, 5000);
    }
});

// Listen for appinstalled event to clean up
window.addEventListener('appinstalled', () => {
    localStorage.setItem('pwa_install_dismissed','1');
    hideInstallPrompt();
});
</script>
</html>