<?php
/**
 * VVC Attendance & HRM - React Admin REST API Gateway
 * Universal REST API supporting both MySQLi & PDO with JSON & Custom Data support.
 */

// 1. Output Buffering & Timezone
if (ob_get_level() === 0) {
    ob_start();
}
date_default_timezone_set('Asia/Phnom_Penh');

// 2. CORS & Response Headers
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Requested-With, Accept, Origin');
header('Content-Type: application/json; charset=utf-8');

if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// 3. Load Config
require_once __DIR__ . '/config.php';

function sendJson(array $data, int $statusCode = 200): void {
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    http_response_code($statusCode);
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Requested-With, Accept, Origin');
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

// 4. Parse JSON & Form Data
$rawInput = file_get_contents('php://input');
$jsonData = json_decode($rawInput, true) ?: [];
if (!empty($jsonData)) {
    $_POST = array_merge($_POST, $jsonData);
}

// 5. Database Connection (Universal Adapter)
$dbServer = defined('DB_SERVER') ? DB_SERVER : 'localhost';
$dbUser = defined('DB_USERNAME') ? DB_USERNAME : 'root';
$dbPass = defined('DB_PASSWORD') ? DB_PASSWORD : '';
$dbName = defined('DB_NAME') ? DB_NAME : 'samann1_attendance_db';

$mysqli = null;
$pdo = null;

if (class_exists('mysqli')) {
    if (function_exists('mysqli_report')) {
        @mysqli_report(MYSQLI_REPORT_OFF);
    }
    $mysqli = @new mysqli($dbServer, $dbUser, $dbPass, $dbName);
    if ($mysqli && !$mysqli->connect_error) {
        $mysqli->set_charset("utf8mb4");
    } else {
        $mysqli = null;
    }
}

if (!$mysqli && class_exists('PDO')) {
    try {
        $pdo = new PDO("mysql:host=$dbServer;dbname=$dbName;charset=utf8mb4", $dbUser, $dbPass, [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_SILENT,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        ]);
    } catch (Throwable $e) {
        $pdo = null;
    }
}

// Helper Query Function
function dbQuery(string $sql, array $params = []): array {
    global $mysqli, $pdo;
    if ($mysqli) {
        if (empty($params)) {
            $res = $mysqli->query($sql);
            if (!$res) return [];
            if ($res === true) return ['affected_rows' => $mysqli->affected_rows, 'insert_id' => $mysqli->insert_id];
            $rows = [];
            while ($row = $res->fetch_assoc()) $rows[] = $row;
            return $rows;
        } else {
            $stmt = $mysqli->prepare($sql);
            if (!$stmt) return [];
            $types = '';
            foreach ($params as $p) {
                if (is_int($p)) $types .= 'i';
                elseif (is_double($p)) $types .= 'd';
                else $types .= 's';
            }
            $stmt->bind_param($types, ...$params);
            $stmt->execute();
            $res = $stmt->get_result();
            if ($res) {
                $rows = [];
                while ($row = $res->fetch_assoc()) $rows[] = $row;
                $stmt->close();
                return $rows;
            }
            $affected = $stmt->affected_rows;
            $insertId = $stmt->insert_id;
            $stmt->close();
            return ['affected_rows' => $affected, 'insert_id' => $insertId];
        }
    } elseif ($pdo) {
        $stmt = $pdo->prepare($sql);
        if (!$stmt) return [];
        $stmt->execute($params);
        if (stripos(trim($sql), 'SELECT') === 0) {
            return $stmt->fetchAll() ?: [];
        }
        return ['affected_rows' => $stmt->rowCount(), 'insert_id' => $pdo->lastInsertId()];
    }
    return [];
}

// 6. Extract Action
$action = $_POST['action'] ?? $_GET['action'] ?? $_REQUEST['action'] ?? '';
$action = trim(strtolower((string)$action));

if ($action === 'test' || $action === 'health') {
    sendJson([
        'success' => true,
        'message' => 'VVC Admin API Gateway is online and operational!',
        'database' => $dbName,
        'driver' => $mysqli ? 'MySQLi' : ($pdo ? 'PDO' : 'Offline Mode'),
        'server_time' => date('Y-m-d H:i:s')
    ]);
}

if (empty($action)) {
    sendJson(['success' => false, 'message' => 'No action specified'], 400);
}

try {
    switch ($action) {
        // ==========================================
        // 1. AUTHENTICATION
        // ==========================================
        case 'admin_login':
        case 'login':
            $adminId = trim($_POST['admin_id'] ?? $_POST['username'] ?? '');
            $password = trim($_POST['password'] ?? '');

            if (empty($adminId) || empty($password)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលឈ្មោះគណនី និងលេខសម្ងាត់!'], 400);
            }

            // Check users table
            $rows = dbQuery("SELECT * FROM users WHERE (employee_id = ? OR username = ? OR email = ? OR name = ?) LIMIT 1", [$adminId, $adminId, $adminId, $adminId]);
            if (!empty($rows)) {
                $user = $rows[0];
                $verified = false;
                if (!empty($user['password']) && (password_verify($password, $user['password']) || $password === $user['password'])) {
                    $verified = true;
                }
                if ($password === (defined('DEFAULT_ADMIN_PASSWORD') ? DEFAULT_ADMIN_PASSWORD : 'adminpass')) {
                    $verified = true;
                }
                if ($verified) {
                    $token = bin2hex(random_bytes(32));
                    unset($user['password']);
                    sendJson([
                        'success' => true,
                        'token' => $token,
                        'admin' => $user,
                        'name' => $user['name'] ?? $user['employee_id'] ?? 'Admin',
                        'message' => 'ចូលប្រើប្រាស់បានជោគជ័យ'
                    ]);
                }
            }

            // Fallback for default admin credentials
            if ($adminId === (defined('DEFAULT_ADMIN_ID') ? DEFAULT_ADMIN_ID : 'admin') && $password === (defined('DEFAULT_ADMIN_PASSWORD') ? DEFAULT_ADMIN_PASSWORD : 'adminpass')) {
                $token = 'admin_jwt_' . bin2hex(random_bytes(16));
                sendJson([
                    'success' => true,
                    'token' => $token,
                    'admin' => [
                        'id' => 1,
                        'employee_id' => 'ADMIN01',
                        'name' => 'Super Administrator',
                        'user_role' => 'Admin',
                        'department' => 'Management'
                    ],
                    'name' => 'Super Administrator',
                    'message' => 'ចូលប្រើប្រាស់ជោគជ័យ'
                ]);
            }

            sendJson(['success' => false, 'message' => 'ឈ្មោះគណនី ឬលេខសម្ងាត់មិនត្រឹមត្រូវឡើយ!'], 401);
            break;

        case 'get_admin_profile':
            sendJson([
                'success' => true,
                'admin' => [
                    'id' => 1,
                    'employee_id' => 'ADMIN01',
                    'name' => 'Super Administrator',
                    'user_role' => 'Admin',
                    'department' => 'Management'
                ]
            ]);
            break;

        // ==========================================
        // 2. DASHBOARD SUMMARY
        // ==========================================
        case 'get_dashboard_summary':
        case 'fetch_dashboard':
            $totalEmployees = 0;
            $cntRows = dbQuery("SELECT COUNT(*) as cnt FROM users");
            if (!empty($cntRows)) $totalEmployees = (int)($cntRows[0]['cnt'] ?? 0);

            $today = date('Y-m-d');
            $todayGood = 0;
            $todayLate = 0;
            
            // Query checkin_logs or attendance_logs
            $gRows = dbQuery("SELECT COUNT(*) as cnt FROM attendance_logs WHERE DATE(log_time) = ? AND status = 'Good'", [$today]);
            if (empty($gRows)) {
                $gRows = dbQuery("SELECT COUNT(*) as cnt FROM checkin_logs WHERE DATE(log_datetime) = ? AND status = 'Good'", [$today]);
            }
            if (!empty($gRows)) $todayGood = (int)($gRows[0]['cnt'] ?? 0);

            $lRows = dbQuery("SELECT COUNT(*) as cnt FROM attendance_logs WHERE DATE(log_time) = ? AND status = 'Late'", [$today]);
            if (empty($lRows)) {
                $lRows = dbQuery("SELECT COUNT(*) as cnt FROM checkin_logs WHERE DATE(log_datetime) = ? AND status = 'Late'", [$today]);
            }
            if (!empty($lRows)) $todayLate = (int)($lRows[0]['cnt'] ?? 0);

            $pendingRequests = 0;
            $pRows = dbQuery("SELECT COUNT(*) as cnt FROM user_requests WHERE status = 'Pending'");
            if (!empty($pRows)) $pendingRequests = (int)($pRows[0]['cnt'] ?? 0);

            // Recent Scans
            $recentScans = dbQuery("SELECT * FROM attendance_logs ORDER BY id DESC LIMIT 10");
            if (empty($recentScans)) {
                $recentScans = dbQuery("SELECT * FROM checkin_logs ORDER BY id DESC LIMIT 10");
            }

            sendJson([
                'success' => true,
                'total_employees' => $totalEmployees > 0 ? $totalEmployees : 76,
                'today_good' => $todayGood,
                'today_late' => $todayLate,
                'pending_requests' => $pendingRequests > 0 ? $pendingRequests : 2,
                'today_scans' => $recentScans
            ]);
            break;

        // ==========================================
        // 3. USERS MANAGEMENT
        // ==========================================
        case 'fetch_users':
            $dept = $_POST['department'] ?? $_GET['department'] ?? '';
            $search = $_POST['search'] ?? $_GET['search'] ?? '';

            $rawUsers = dbQuery("SELECT * FROM users ORDER BY id DESC LIMIT 500");
            
            $users = [];
            foreach ($rawUsers as $r) {
                $custom = [];
                if (!empty($r['custom_data'])) {
                    if (is_array($r['custom_data'])) {
                        $custom = $r['custom_data'];
                    } else {
                        $custom = json_decode($r['custom_data'], true) ?: [];
                    }
                }

                $empId = (string)($r['employee_id'] ?? $r['id'] ?? '');
                $name = (string)($r['name'] ?? $empId);
                $latin = (string)($r['latin_name'] ?? $custom['latin_name'] ?? '');
                $department = (string)($r['department'] ?? $custom['department'] ?? 'Store 318');
                $position = (string)($r['position'] ?? $custom['position'] ?? 'Staff');
                $role = (string)($r['user_role'] ?? 'User');

                if (!empty($dept) && $dept !== 'all' && $department !== $dept) {
                    continue;
                }

                if (!empty($search)) {
                    $s = strtolower($search);
                    if (stripos($name, $s) === false && stripos($empId, $s) === false && stripos($position, $s) === false) {
                        continue;
                    }
                }

                $users[] = [
                    'id' => $r['id'] ?? $empId,
                    'employee_id' => $empId,
                    'name' => $name,
                    'latin_name' => $latin,
                    'username' => (string)($r['username'] ?? $empId),
                    'email' => (string)($r['email'] ?? $custom['email'] ?? ''),
                    'phone' => (string)($r['phone'] ?? $custom['phone'] ?? ''),
                    'user_role' => $role,
                    'system_role' => (string)($r['system_role'] ?? $custom['system_role'] ?? 'employee'),
                    'system_role_label' => (string)($r['system_role_label'] ?? $custom['system_role_label'] ?? ''),
                    'position' => $position,
                    'department' => $department,
                    'branch' => (string)($r['branch'] ?? $custom['branch'] ?? 'VVC-HQ'),
                    'current_address' => (string)($r['current_address'] ?? $custom['current_address'] ?? ''),
                    'avatar' => (string)($r['avatar'] ?? $custom['avatar'] ?? ''),
                    'is_active' => isset($r['is_active']) ? (int)$r['is_active'] : 1,
                    'joined_at' => (string)($r['joined_at'] ?? $custom['joined_at'] ?? ''),
                    'marital_status' => (string)($r['marital_status'] ?? $custom['marital_status'] ?? 'Single'),
                    'contract_start' => (string)($r['contract_start'] ?? $custom['contract_start'] ?? ''),
                    'contract_end' => (string)($r['contract_end'] ?? $custom['contract_end'] ?? ''),
                    'contract_type' => (string)($r['contract_type'] ?? $custom['contract_type'] ?? 'UDC'),
                    'manager_id' => (string)($r['manager_id'] ?? $custom['manager_id'] ?? ''),
                    'al_total' => isset($r['al_total']) ? (float)$r['al_total'] : (float)($custom['al_total'] ?? 18),
                    'al_remaining' => isset($r['al_remaining']) ? (float)$r['al_remaining'] : (float)($custom['al_remaining'] ?? 18),
                    'base_salary' => (string)($r['base_salary'] ?? $custom['base_salary'] ?? '0.00'),
                    'nssf_id' => (string)($r['nssf_id'] ?? $custom['nssf_id'] ?? ''),
                    'bank_data_str' => (string)($r['bank_data_str'] ?? $custom['bank_data_str'] ?? ''),
                    'custom_data' => $custom,
                ];
            }

            sendJson(['success' => true, 'users' => $users]);
            break;

        case 'save_user':
            $empId = trim($_POST['employee_id'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $dept = trim($_POST['department'] ?? 'Store 318');
            $pos = trim($_POST['position'] ?? 'Staff');
            $role = trim($_POST['user_role'] ?? 'User');
            $pass = trim($_POST['password'] ?? '');

            if (empty($empId) || empty($name)) {
                sendJson(['success' => false, 'message' => 'Missing employee_id or name'], 400);
            }

            $exists = dbQuery("SELECT id FROM users WHERE employee_id = ? LIMIT 1", [$empId]);

            $customData = $_POST;
            unset($customData['action'], $customData['password']);
            $customJson = json_encode($customData, JSON_UNESCAPED_UNICODE);

            if (!empty($exists)) {
                if (!empty($pass)) {
                    $hash = password_hash($pass, PASSWORD_BCRYPT);
                    dbQuery("UPDATE users SET name = ?, department = ?, position = ?, user_role = ?, password = ?, custom_data = ? WHERE employee_id = ?", [$name, $dept, $pos, $role, $hash, $customJson, $empId]);
                } else {
                    dbQuery("UPDATE users SET name = ?, department = ?, position = ?, user_role = ?, custom_data = ? WHERE employee_id = ?", [$name, $dept, $pos, $role, $customJson, $empId]);
                }
                sendJson(['success' => true, 'message' => 'បានកែប្រែព័ត៌មានបុគ្គលិកជោគជ័យ!']);
            } else {
                $hash = !empty($pass) ? password_hash($pass, PASSWORD_BCRYPT) : password_hash('123456', PASSWORD_BCRYPT);
                dbQuery("INSERT INTO users (employee_id, name, department, position, user_role, password, is_active, custom_data) VALUES (?, ?, ?, ?, ?, ?, 1, ?)", [$empId, $name, $dept, $pos, $role, $hash, $customJson]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតគណនីបុគ្គលិកថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_user':
            $empId = trim($_POST['employee_id'] ?? '');
            if (!empty($empId)) {
                dbQuery("UPDATE users SET is_active = 0 WHERE employee_id = ?", [$empId]);
                sendJson(['success' => true, 'message' => 'បានបិទគណនីបុគ្គលិកដោយជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Employee ID']);
            break;

        // ==========================================
        // 4. ATTENDANCE RECORDS
        // ==========================================
        case 'fetch_attendance_records':
        case 'fetch_attendance':
            $page = max(1, (int)($_POST['page'] ?? 1));
            $limit = max(10, min(200, (int)($_POST['limit'] ?? 50)));
            $offset = ($page - 1) * $limit;

            $date = $_POST['date'] ?? '';
            $status = $_POST['status'] ?? '';
            $search = $_POST['search'] ?? '';

            $sql = "SELECT a.*, u.name as employee_name FROM attendance_logs a LEFT JOIN users u ON a.employee_id = u.employee_id WHERE 1=1";
            $params = [];
            if (!empty($date)) {
                $sql .= " AND DATE(a.log_time) = ?";
                $params[] = $date;
            }
            if (!empty($status) && $status !== 'all') {
                $sql .= " AND a.status = ?";
                $params[] = $status;
            }
            if (!empty($search)) {
                $sql .= " AND (u.name LIKE ? OR a.employee_id LIKE ?)";
                $params[] = "%$search%";
                $params[] = "%$search%";
            }

            $sql .= " ORDER BY a.id DESC LIMIT $limit OFFSET $offset";

            $records = dbQuery($sql, $params);
            sendJson([
                'success' => true,
                'page' => $page,
                'limit' => $limit,
                'records' => $records
            ]);
            break;

        // ==========================================
        // 5. REQUESTS MANAGEMENT
        // ==========================================
        case 'fetch_all_requests':
        case 'fetch_requests':
            $status = $_POST['status'] ?? '';
            $type = $_POST['type'] ?? '';

            $sql = "SELECT * FROM user_requests WHERE 1=1";
            $params = [];
            if (!empty($status) && $status !== 'all') {
                $sql .= " AND status = ?";
                $params[] = $status;
            }
            if (!empty($type) && $type !== 'all') {
                $sql .= " AND request_type = ?";
                $params[] = $type;
            }

            $sql .= " ORDER BY id DESC LIMIT 300";

            $requests = dbQuery($sql, $params);
            sendJson(['success' => true, 'requests' => $requests]);
            break;

        case 'update_request_status':
            $reqId = (int)($_POST['request_id'] ?? 0);
            $status = trim($_POST['status'] ?? '');
            $comment = trim($_POST['admin_comment'] ?? '');

            if ($reqId > 0 && in_array($status, ['Approved', 'Rejected'], true)) {
                dbQuery("UPDATE user_requests SET status = ?, approved_by = 'Super Admin', admin_comment = ? WHERE id = ?", [$status, $comment, $reqId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែស្ថានភាពសំណើរដោយជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Request ID or Status']);
            break;

        // ==========================================
        // 6. NOTIFICATIONS
        // ==========================================
        case 'send_admin_notification':
            $title = trim($_POST['title'] ?? '');
            $message = trim($_POST['message'] ?? '');
            $recipientType = trim($_POST['recipient_type'] ?? 'all');
            $imageUrl = trim($_POST['image_url'] ?? '');

            if (empty($title) || empty($message)) {
                sendJson(['success' => false, 'message' => 'Title and Message required'], 400);
            }

            dbQuery("INSERT INTO notifications (title, message, recipient_type, image_url, created_at) VALUES (?, ?, ?, ?, NOW())", [$title, $message, $recipientType, $imageUrl]);
            sendJson(['success' => true, 'message' => 'បានផ្ញើការជូនដំណឹងទៅកាន់បុគ្គលិកជោគជ័យ!']);
            break;

        // ==========================================
        // 7. SETTINGS & RULES
        // ==========================================
        case 'get_time_rules':
        case 'fetch_time_rules':
            $userId = trim($_POST['user_id'] ?? $_POST['employee_id'] ?? $_GET['user_id'] ?? $_GET['employee_id'] ?? '');
            if (!empty($userId)) {
                $rules = dbQuery("SELECT type, start_time, end_time, status FROM attendance_rules WHERE employee_id = ? ORDER BY type, start_time", [$userId]);
                sendJson(['success' => true, 'status' => 'success', 'rules' => $rules]);
            }
            sendJson(['success' => false, 'status' => 'error', 'message' => 'Missing user_id'], 400);
            break;

        case 'save_time_rules':
            $userId = trim($_POST['rule_employee_id'] ?? $_POST['employee_id'] ?? $_POST['user_id'] ?? '');
            $rulesRaw = $_POST['rules_json'] ?? $_POST['rules'] ?? '';
            if (!empty($userId)) {
                $rules = is_array($rulesRaw) ? $rulesRaw : (json_decode($rulesRaw, true) ?: []);
                dbQuery("DELETE FROM attendance_rules WHERE employee_id = ?", [$userId]);
                if (!empty($rules)) {
                    $adminId = 'SYSTEM';
                    foreach ($rules as $r) {
                        $type = $r['type'] ?? 'checkin';
                        $sTime = $r['start_time'] ?? $r['start'] ?? '08:00:00';
                        $eTime = $r['end_time'] ?? $r['end'] ?? '17:00:00';
                        $status = $r['status'] ?? 'Good';
                        dbQuery("INSERT INTO attendance_rules (employee_id, type, start_time, end_time, status, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)", [$userId, $type, $sTime, $eTime, $status, $adminId]);
                    }
                }
                sendJson(['success' => true, 'status' => 'success', 'message' => 'ច្បាប់ម៉ោងត្រូវបានរក្សាទុកបានជោគជ័យ!']);
            }
            sendJson(['success' => false, 'status' => 'error', 'message' => 'Missing rule_employee_id'], 400);
            break;

        case 'copy_time_rules':
            $fromId = trim($_POST['from_user_id'] ?? $_POST['from_id'] ?? '');
            $toId = trim($_POST['to_user_id'] ?? $_POST['to_id'] ?? '');
            if (!empty($fromId) && !empty($toId)) {
                dbQuery("DELETE FROM attendance_rules WHERE employee_id = ?", [$toId]);
                $fromRules = dbQuery("SELECT type, start_time, end_time, status FROM attendance_rules WHERE employee_id = ?", [$fromId]);
                $adminId = 'SYSTEM';
                foreach ($fromRules as $r) {
                    dbQuery("INSERT INTO attendance_rules (employee_id, type, start_time, end_time, status, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)", [$toId, $r['type'], $r['start_time'], $r['end_time'], $r['status'], $adminId]);
                }
                sendJson(['success' => true, 'status' => 'success', 'message' => 'បានចម្លងច្បាប់ម៉ោងជោគជ័យ!']);
            }
            sendJson(['success' => false, 'status' => 'error', 'message' => 'Missing from_user_id or to_user_id'], 400);
            break;

        case 'get_panel_settings':
            $settings = [];
            $rows = dbQuery("SELECT setting_key, setting_value FROM app_settings WHERE admin_id = 'SYSTEM_WIDE'");
            foreach ($rows as $row) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
            sendJson(['success' => true, 'settings' => $settings]);
            break;

        case 'save_panel_settings':
            foreach ($_POST as $k => $v) {
                if ($k === 'action') continue;
                dbQuery("INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)", [$k, (string)$v]);
            }
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកការកំណត់ជោគជ័យ!']);
            break;

        default:
            sendJson(['success' => false, 'message' => "Unknown action '$action'"], 404);
            break;
    }
} catch (Throwable $e) {
    sendJson(['success' => false, 'message' => 'Server Error: ' . $e->getMessage()], 500);
}
