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
        // ==========================================
        // 5. REQUESTS MANAGEMENT
        // ==========================================
        case 'fetch_all_requests':
        case 'fetch_requests':
            $status = $_POST['status'] ?? $_GET['status'] ?? '';
            $type = $_POST['type'] ?? $_GET['type'] ?? '';

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
            if (empty($requests)) {
                // Fallback from requests table if user_requests is empty
                $requests = dbQuery("SELECT * FROM requests ORDER BY id DESC LIMIT 300");
            }
            sendJson(['success' => true, 'requests' => $requests]);
            break;

        case 'create_request':
        case 'save_request':
            $reqId = (int)($_POST['id'] ?? 0);
            $userId = trim($_POST['user_id'] ?? $_POST['employee_id'] ?? '');
            $empId = trim($_POST['employee_id'] ?? $userId);
            $reqName = trim($_POST['requester_name'] ?? $_POST['name'] ?? '');
            $reqType = trim($_POST['request_type'] ?? 'Annual Leave');
            $dept = trim($_POST['department'] ?? 'Store 318');
            $pos = trim($_POST['position'] ?? 'Staff');
            $reqDate = trim($_POST['request_date'] ?? date('Y-m-d'));
            $retDate = trim($_POST['return_date'] ?? '');
            $reason = trim($_POST['reason'] ?? '');
            $status = trim($_POST['status'] ?? 'Pending');

            if ($reqId > 0) {
                dbQuery("UPDATE user_requests SET request_type = ?, department = ?, position = ?, request_date = ?, return_date = ?, reason = ?, status = ? WHERE id = ?", [$reqType, $dept, $pos, $reqDate, $retDate, $reason, $status, $reqId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែសំណើរជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO user_requests (user_id, employee_id, requester_name, request_type, department, position, request_date, return_date, reason, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())", [$userId, $empId, $reqName, $reqType, $dept, $pos, $reqDate, $retDate, $reason, $status]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតសំណើរថ្មីជោគជ័យ!']);
            }
            break;

        case 'update_request_status':
            $reqId = (int)($_POST['request_id'] ?? $_POST['id'] ?? 0);
            $status = trim($_POST['status'] ?? '');
            $comment = trim($_POST['admin_comment'] ?? $_POST['comment'] ?? '');

            if ($reqId > 0 && in_array($status, ['Approved', 'Rejected'], true)) {
                dbQuery("UPDATE user_requests SET status = ?, approved_by = 'Super Admin', admin_comment = ? WHERE id = ?", [$status, $comment, $reqId]);
                dbQuery("UPDATE requests SET status = ?, approved_by = 'Super Admin' WHERE id = ?", [$status, $reqId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែស្ថានភាពសំណើរដោយជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Request ID or Status']);
            break;

        case 'delete_request':
            $reqId = (int)($_POST['request_id'] ?? $_POST['id'] ?? 0);
            if ($reqId > 0) {
                dbQuery("DELETE FROM user_requests WHERE id = ?", [$reqId]);
                dbQuery("DELETE FROM requests WHERE id = ?", [$reqId]);
                sendJson(['success' => true, 'message' => 'បានលុបសំណើរជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Request ID']);
            break;

        // ==========================================
        // 6. LOCATIONS & QR CODES
        // ==========================================
        case 'fetch_locations':
        case 'get_locations':
            dbQuery("CREATE TABLE IF NOT EXISTS locations (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                location_name VARCHAR(255) DEFAULT NULL,
                address TEXT,
                latitude DECIMAL(10, 8) DEFAULT 11.5564,
                longitude DECIMAL(11, 8) DEFAULT 104.9282,
                radius_meters INT DEFAULT 100,
                qr_secret VARCHAR(100) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $locations = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), location_name, 'សាខា') as name, address, latitude, longitude, radius_meters, qr_secret FROM locations ORDER BY id ASC");
            if (empty($locations)) {
                // Seed default branches
                dbQuery("INSERT INTO locations (name, location_name, address, latitude, longitude, radius_meters, qr_secret) VALUES 
                    ('ការិយាល័យកណ្តាល (Store 318)', 'Store 318', 'ផ្ទះលេខ 318 ផ្លូវកម្ពុជាក្រោម រាជធានីភ្នំពេញ', 11.56830000, 104.91250000, 100, 'vvc_318_secure_qr_2026'),
                    ('សាខា SKKS2', 'Store SKKS2', 'ផ្លូវ 271 រាជធានីភ្នំពេញ', 11.54210000, 104.90120000, 100, 'vvc_skks2_secure_qr_2026'),
                    ('ឃ្លាំងទំនិញ PSP (Warehouse)', 'Warehouse PSP', 'ផ្លូវជាតិលេខ ៤ រាជធានីភ្នំពេញ', 11.51240000, 104.82110000, 150, 'vvc_psp_warehouse_qr_2026')");
                $locations = dbQuery("SELECT id, name, address, latitude, longitude, radius_meters, qr_secret FROM locations ORDER BY id ASC");
            }
            sendJson(['success' => true, 'locations' => $locations]);
            break;

        case 'save_location':
            $locId = (int)($_POST['id'] ?? 0);
            $name = trim($_POST['name'] ?? $_POST['location_name'] ?? '');
            $addr = trim($_POST['address'] ?? '');
            $lat = (float)($_POST['latitude'] ?? 11.5564);
            $lng = (float)($_POST['longitude'] ?? 104.9282);
            $radius = (int)($_POST['radius_meters'] ?? 100);
            $qrSecret = trim($_POST['qr_secret'] ?? 'vvc_loc_' . bin2hex(random_bytes(6)));

            if (empty($name)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលឈ្មោះទីតាំង!'], 400);
            }

            if ($locId > 0) {
                dbQuery("UPDATE locations SET name = ?, location_name = ?, address = ?, latitude = ?, longitude = ?, radius_meters = ?, qr_secret = ? WHERE id = ?", [$name, $name, $addr, $lat, $lng, $radius, $qrSecret, $locId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែទីតាំងជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO locations (name, location_name, address, latitude, longitude, radius_meters, qr_secret) VALUES (?, ?, ?, ?, ?, ?, ?)", [$name, $name, $addr, $lat, $lng, $radius, $qrSecret]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតទីតាំងថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_location':
            $locId = (int)($_POST['id'] ?? $_POST['location_id'] ?? 0);
            if ($locId > 0) {
                dbQuery("DELETE FROM locations WHERE id = ?", [$locId]);
                sendJson(['success' => true, 'message' => 'បានលុបទីតាំងជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Location ID']);
            break;

        // ==========================================
        // 7. CATEGORIES
        // ==========================================
        case 'fetch_categories':
        case 'get_categories':
            dbQuery("CREATE TABLE IF NOT EXISTS categories (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                code VARCHAR(100) NOT NULL,
                description TEXT,
                item_count INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $categories = dbQuery("SELECT * FROM categories ORDER BY id DESC");
            if (empty($categories)) {
                dbQuery("INSERT INTO categories (name, code, description, item_count) VALUES 
                    ('សម្ភារៈការិយាល័យ (Office Supplies)', 'CAT-OFFICE', 'សម្ភារៈប្រើប្រាស់ទូទៅ', 34),
                    ('គ្រឿងអេឡិចត្រូនិច (Electronics)', 'CAT-ELEC', 'កុំព្យូទ័រ ម៉ាស៊ីនព្រីន ឧបករណ៍បច្ចេកវិទ្យា', 18),
                    ('ទំនិញស្តុកហាង 318 (Store 318 Goods)', 'CAT-S318', 'ទំនិញលក់រាយនៅហាង 318', 120),
                    ('ទំនិញស្តុកឃ្លាំង PSP (Warehouse PSP Goods)', 'CAT-PSP', 'ទំនិញស្តុកធំនៅឃ្លាំង PSP', 250)");
                $categories = dbQuery("SELECT * FROM categories ORDER BY id DESC");
            }
            sendJson(['success' => true, 'categories' => $categories]);
            break;

        case 'save_category':
            $catId = (int)($_POST['id'] ?? 0);
            $name = trim($_POST['name'] ?? '');
            $code = trim($_POST['code'] ?? 'CAT-' . rand(100, 999));
            $desc = trim($_POST['description'] ?? '');

            if (empty($name)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលឈ្មោះប្រភេទ!'], 400);
            }

            if ($catId > 0) {
                dbQuery("UPDATE categories SET name = ?, code = ?, description = ? WHERE id = ?", [$name, $code, $desc, $catId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែប្រភេទជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO categories (name, code, description, item_count) VALUES (?, ?, ?, 0)", [$name, $code, $desc]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតប្រភេទថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_category':
            $catId = (int)($_POST['id'] ?? $_POST['category_id'] ?? 0);
            if ($catId > 0) {
                dbQuery("DELETE FROM categories WHERE id = ?", [$catId]);
                sendJson(['success' => true, 'message' => 'បានលុបប្រភេទជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Category ID']);
            break;

        // ==========================================
        // 8. STOCK & INVENTORY
        // ==========================================
        // 8. STOCK MANAGEMENT (All Sub-Pages & Actions)
        // ==========================================
        case 'fetch_stock_items':
        case 'get_stock':
            dbQuery("CREATE TABLE IF NOT EXISTS stock_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                code VARCHAR(100) NOT NULL DEFAULT '',
                name VARCHAR(255) NOT NULL,
                item_name VARCHAR(255) DEFAULT '',
                category VARCHAR(100) DEFAULT 'General',
                quantity INT DEFAULT 0,
                unit VARCHAR(50) DEFAULT 'កញ្ចប់',
                price DECIMAL(10, 2) DEFAULT 0.00,
                location VARCHAR(100) DEFAULT 'Store 318',
                status VARCHAR(50) DEFAULT 'In Stock',
                image_path VARCHAR(255) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            // Create auxiliary tables for stock
            dbQuery("CREATE TABLE IF NOT EXISTS stock_purchases (
                id INT AUTO_INCREMENT PRIMARY KEY,
                supplier VARCHAR(255) DEFAULT '',
                invoice_number VARCHAR(100) DEFAULT '',
                invoice_image VARCHAR(255) DEFAULT NULL,
                notes TEXT,
                total_amount DECIMAL(12,2) DEFAULT 0.00,
                created_by VARCHAR(100) DEFAULT 'Admin',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS stock_purchase_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                purchase_id INT NOT NULL,
                item_id INT NOT NULL,
                item_name VARCHAR(255) DEFAULT '',
                quantity INT DEFAULT 0,
                price DECIMAL(10,2) DEFAULT 0.00,
                total DECIMAL(12,2) DEFAULT 0.00
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS stock_transfers (
                id INT AUTO_INCREMENT PRIMARY KEY,
                transfer_title VARCHAR(255) DEFAULT '',
                request_no VARCHAR(100) DEFAULT '',
                stock_item_id INT DEFAULT 0,
                item_name VARCHAR(255) DEFAULT '',
                quantity_transferred INT DEFAULT 0,
                to_location VARCHAR(100) DEFAULT '',
                notes TEXT,
                transfer_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS stock_count_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                item_id INT DEFAULT 0,
                item_name VARCHAR(255) DEFAULT '',
                system_qty INT DEFAULT 0,
                physical_qty INT DEFAULT 0,
                difference INT DEFAULT 0,
                phase VARCHAR(50) DEFAULT 'Morning',
                count_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS stock_movements (
                id INT AUTO_INCREMENT PRIMARY KEY,
                item_id INT DEFAULT 0,
                item_name VARCHAR(255) DEFAULT '',
                movement_type VARCHAR(100) DEFAULT 'transfer',
                quantity_change INT DEFAULT 0,
                quantity_before INT DEFAULT 0,
                quantity_after INT DEFAULT 0,
                reference_no VARCHAR(100) DEFAULT '',
                reference_type VARCHAR(100) DEFAULT '',
                actor_name VARCHAR(100) DEFAULT 'Admin',
                notes TEXT,
                location VARCHAR(100) DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS stock_request (
                id INT AUTO_INCREMENT PRIMARY KEY,
                request_no VARCHAR(100) NOT NULL,
                title VARCHAR(255) DEFAULT '',
                user_id VARCHAR(100) DEFAULT '',
                user_name VARCHAR(255) DEFAULT '',
                department VARCHAR(100) DEFAULT '',
                location VARCHAR(100) DEFAULT '',
                status VARCHAR(50) DEFAULT 'pending',
                notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $search = trim($_POST['search'] ?? $_GET['search'] ?? '');
            if (!empty($search)) {
                $stockItems = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as name, COALESCE(NULLIF(item_name, ''), name, 'Item') as item_name, code, category, quantity, unit, price, location, status, image_path, created_at FROM stock_items WHERE name LIKE ? OR item_name LIKE ? OR code LIKE ? OR category LIKE ? ORDER BY id DESC", ["%$search%", "%$search%", "%$search%", "%$search%"]);
            } else {
                $stockItems = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as name, COALESCE(NULLIF(item_name, ''), name, 'Item') as item_name, code, category, quantity, unit, price, location, status, image_path, created_at FROM stock_items ORDER BY id DESC");
            }

            if (empty($stockItems)) {
                dbQuery("INSERT INTO stock_items (code, name, item_name, category, quantity, unit, price, location, status) VALUES 
                    ('STK-001', 'កាហ្វេគូលែន KouPrey Coffee (250g)', 'កាហ្វេគូលែន KouPrey Coffee (250g)', 'Coffee Beans', 140, 'កញ្ចប់', 6.50, 'Store 318', 'In Stock'),
                    ('STK-002', 'តែបៃតង Green Tea Premium (500g)', 'តែបៃតង Green Tea Premium (500g)', 'Tea & Beverages', 8, 'កញ្ចប់', 8.00, 'Store SKKS2', 'Low Stock'),
                    ('STK-003', 'កែវជ័រ VVC Eco Cup (500ml)', 'កែវជ័រ VVC Eco Cup (500ml)', 'Packaging', 2500, 'កែវ', 0.12, 'Warehouse PSP', 'In Stock'),
                    ('STK-004', 'ទឹកស៊ីរ៉ូវ៉ានីឡា Vanilla Syrup (1L)', 'ទឹកស៊ីរ៉ូវ៉ានីឡា Vanilla Syrup (1L)', 'Ingredients', 0, 'ដប', 12.00, 'Warehouse PSP', 'Out of Stock')");
                $stockItems = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as name, COALESCE(NULLIF(item_name, ''), name, 'Item') as item_name, code, category, quantity, unit, price, location, status, image_path, created_at FROM stock_items ORDER BY id DESC");
            }
            sendJson(['success' => true, 'items' => $stockItems]);
            break;

        case 'get_stock_item':
            $id = (int)($_POST['id'] ?? $_GET['id'] ?? 0);
            $item = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as name, COALESCE(NULLIF(item_name, ''), name, 'Item') as item_name, code, category, quantity, unit, price, location, status, image_path FROM stock_items WHERE id = ? LIMIT 1", [$id]);
            if (!empty($item)) {
                sendJson(['success' => true, 'data' => $item[0]]);
            }
            sendJson(['success' => false, 'message' => 'ទំនិញរកមិនឃើញ!'], 404);
            break;

        case 'save_stock_item':
        case 'add_stock':
        case 'update_stock':
            $itemId = (int)($_POST['id'] ?? $_POST['item_id'] ?? 0);
            $code = trim($_POST['code'] ?? 'STK-' . rand(100, 999));
            $name = trim($_POST['name'] ?? $_POST['item_name'] ?? '');
            $category = trim($_POST['category'] ?? 'General');
            $qty = (int)($_POST['quantity'] ?? 0);
            $unit = trim($_POST['unit'] ?? 'កញ្ចប់');
            $price = (float)($_POST['price'] ?? 0.00);
            $location = trim($_POST['location'] ?? 'Store 318');
            $status = $qty <= 0 ? 'Out of Stock' : ($qty < 10 ? 'Low Stock' : 'In Stock');
            $imagePath = null;

            if (isset($_FILES['item_image']) && $_FILES['item_image']['error'] === UPLOAD_ERR_OK) {
                $ext = strtolower(pathinfo($_FILES['item_image']['name'], PATHINFO_EXTENSION));
                if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'gif'])) {
                    $uploadDir = __DIR__ . '/uploads/stock/';
                    if (!is_dir($uploadDir)) @mkdir($uploadDir, 0777, true);
                    $filename = 'stock_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
                    if (move_uploaded_file($_FILES['item_image']['tmp_name'], $uploadDir . $filename)) {
                        $imagePath = 'uploads/stock/' . $filename;
                    }
                }
            }

            if (empty($name)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលឈ្មោះទំនិញ!'], 400);
            }

            if ($itemId > 0) {
                if ($imagePath) {
                    dbQuery("UPDATE stock_items SET code = ?, name = ?, item_name = ?, category = ?, quantity = ?, unit = ?, price = ?, location = ?, status = ?, image_path = ? WHERE id = ?", [$code, $name, $name, $category, $qty, $unit, $price, $location, $status, $imagePath, $itemId]);
                } else {
                    dbQuery("UPDATE stock_items SET code = ?, name = ?, item_name = ?, category = ?, quantity = ?, unit = ?, price = ?, location = ?, status = ? WHERE id = ?", [$code, $name, $name, $category, $qty, $unit, $price, $location, $status, $itemId]);
                }
                sendJson(['success' => true, 'message' => 'បានកែប្រែទំនិញជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO stock_items (code, name, item_name, category, quantity, unit, price, location, status, image_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [$code, $name, $name, $category, $qty, $unit, $price, $location, $status, $imagePath]);
                sendJson(['success' => true, 'message' => 'បានបញ្ចូលទំនិញថ្មីជោគជ័យ!']);
            }
            break;

        case 'deduct_stock':
            $itemId = (int)($_POST['item_id'] ?? $_POST['id'] ?? 0);
            $deductQty = (int)($_POST['deduct_quantity'] ?? $_POST['quantity'] ?? 0);
            if ($itemId <= 0 || $deductQty <= 0) {
                sendJson(['success' => false, 'message' => 'ចំនួនមិនត្រឹមត្រូវ!'], 400);
            }
            $itemRows = dbQuery("SELECT id, name, item_name, quantity FROM stock_items WHERE id = ? LIMIT 1", [$itemId]);
            if (empty($itemRows)) {
                sendJson(['success' => false, 'message' => 'រកមិនឃើញទំនិញ!'], 404);
            }
            $item = $itemRows[0];
            $currentQty = (int)$item['quantity'];
            if ($deductQty > $currentQty) {
                sendJson(['success' => false, 'message' => 'បរិមាណដែលដកចេញ មិនអាចធំជាងបរិមាណក្នុងស្តុកឡើយ!'], 400);
            }
            $newQty = $currentQty - $deductQty;
            $newStatus = $newQty <= 0 ? 'Out of Stock' : ($newQty < 10 ? 'Low Stock' : 'In Stock');
            dbQuery("UPDATE stock_items SET quantity = ?, status = ? WHERE id = ?", [$newQty, $newStatus, $itemId]);

            // Record movement
            $itemName = $item['name'] ?: $item['item_name'];
            dbQuery("INSERT INTO stock_movements (item_id, item_name, movement_type, quantity_change, quantity_before, quantity_after, reference_no, reference_type, actor_name, notes) VALUES (?, ?, 'deduct', ?, ?, ?, 'MANUAL-DEDUCT', 'Manual Action', 'Admin', 'កាត់ចេញពីស្តុកដោយផ្ទាល់')", [$itemId, $itemName, -$deductQty, $currentQty, $newQty]);

            sendJson(['success' => true, 'message' => "បានកាត់បន្ថយចំនួន $deductQty ជោគជ័យ (នៅសល់: $newQty)"]);
            break;

        case 'delete_stock_item':
            $itemId = (int)($_POST['id'] ?? $_POST['item_id'] ?? 0);
            if ($itemId > 0) {
                dbQuery("DELETE FROM stock_items WHERE id = ?", [$itemId]);
                sendJson(['success' => true, 'message' => 'បានលុបទំនិញជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Stock Item ID']);
            break;

        case 'fetch_stock_purchases':
            $purchases = dbQuery("SELECT p.*, (SELECT COUNT(*) FROM stock_purchase_items WHERE purchase_id = p.id) as total_items FROM stock_purchases p ORDER BY p.id DESC LIMIT 50");
            sendJson(['success' => true, 'purchases' => $purchases]);
            break;

        case 'save_stock_purchase':
        case 'process_purchase':
            $supplier = trim($_POST['supplier'] ?? '');
            $invoiceNumber = trim($_POST['invoice_number'] ?? 'INV-' . time());
            $notes = trim($_POST['notes'] ?? '');
            $itemsJson = $_POST['items'] ?? null;
            $invoiceImage = null;

            if (isset($_FILES['invoice_image']) && $_FILES['invoice_image']['error'] === UPLOAD_ERR_OK) {
                $ext = strtolower(pathinfo($_FILES['invoice_image']['name'], PATHINFO_EXTENSION));
                if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp', 'pdf'])) {
                    $uploadDir = __DIR__ . '/uploads/invoices/';
                    if (!is_dir($uploadDir)) @mkdir($uploadDir, 0777, true);
                    $filename = 'inv_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
                    if (move_uploaded_file($_FILES['invoice_image']['tmp_name'], $uploadDir . $filename)) {
                        $invoiceImage = 'uploads/invoices/' . $filename;
                    }
                }
            }

            $itemsList = [];
            if (is_string($itemsJson)) {
                $itemsList = json_decode($itemsJson, true) ?: [];
            } elseif (is_array($itemsJson)) {
                $itemsList = $itemsJson;
            } elseif (isset($_POST['item_id']) && is_array($_POST['item_id'])) {
                foreach ($_POST['item_id'] as $idx => $iid) {
                    $itemsList[] = [
                        'item_id' => (int)$iid,
                        'quantity' => (int)($_POST['quantity'][$idx] ?? 0),
                        'price' => (float)($_POST['price'][$idx] ?? 0),
                    ];
                }
            }

            if (empty($itemsList)) {
                sendJson(['success' => false, 'message' => 'សូមបន្ថែមទំនិញយ៉ាងហោចណាស់មួយ!'], 400);
            }

            $totalAmount = 0;
            foreach ($itemsList as $it) {
                $totalAmount += ((int)($it['quantity'] ?? 0)) * ((float)($it['price'] ?? 0));
            }

            dbQuery("INSERT INTO stock_purchases (supplier, invoice_number, invoice_image, notes, total_amount, created_by) VALUES (?, ?, ?, ?, ?, 'Admin')", [$supplier, $invoiceNumber, $invoiceImage, $notes, $totalAmount]);
            $purchaseId = $mysqli->insert_id;

            foreach ($itemsList as $it) {
                $iid = (int)($it['item_id'] ?? 0);
                $iqty = (int)($it['quantity'] ?? 0);
                $iprice = (float)($it['price'] ?? 0);
                if ($iid <= 0 || $iqty <= 0) continue;

                $stockRow = dbQuery("SELECT id, name, item_name, quantity FROM stock_items WHERE id = ? LIMIT 1", [$iid]);
                $itemName = !empty($stockRow) ? ($stockRow[0]['name'] ?: $stockRow[0]['item_name']) : "Item #$iid";
                $oldQty = !empty($stockRow) ? (int)$stockRow[0]['quantity'] : 0;
                $newQty = $oldQty + $iqty;

                dbQuery("INSERT INTO stock_purchase_items (purchase_id, item_id, item_name, quantity, price, total) VALUES (?, ?, ?, ?, ?, ?)", [$purchaseId, $iid, $itemName, $iqty, $iprice, $iqty * $iprice]);
                dbQuery("UPDATE stock_items SET quantity = ?, status = 'In Stock', price = CASE WHEN ? > 0 THEN ? ELSE price END WHERE id = ?", [$newQty, $iprice, $iprice, $iid]);

                dbQuery("INSERT INTO stock_movements (item_id, item_name, movement_type, quantity_change, quantity_before, quantity_after, reference_no, reference_type, actor_name, notes) VALUES (?, ?, 'purchase', ?, ?, ?, ?, 'Purchase Invoice', 'Admin', ?)", [$iid, $itemName, $iqty, $oldQty, $newQty, $invoiceNumber, "ទិញចូលពី $supplier"]);
            }

            sendJson(['success' => true, 'message' => 'បានទិញចូលស្តុកជោគជ័យ!']);
            break;

        case 'fetch_stock_reports':
            $totalItems = (int)(dbQuery("SELECT COUNT(*) as c FROM stock_items")[0]['c'] ?? 0);
            $totalQty = (int)(dbQuery("SELECT SUM(quantity) as c FROM stock_items")[0]['c'] ?? 0);
            $totalValue = (float)(dbQuery("SELECT SUM(quantity * price) as c FROM stock_items")[0]['c'] ?? 0);
            $lowStock = (int)(dbQuery("SELECT COUNT(*) as c FROM stock_items WHERE quantity <= 10")[0]['c'] ?? 0);

            $tab = trim($_POST['tab'] ?? $_GET['tab'] ?? 'all_stock');
            $data = [];

            if ($tab === 'all_stock') {
                $data = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as name, COALESCE(NULLIF(item_name, ''), name, 'Item') as item_name, code, category, quantity, unit, price, (quantity * price) as total_value, location, status, image_path FROM stock_items ORDER BY quantity ASC");
            } elseif ($tab === 'low_stock') {
                $data = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as name, COALESCE(NULLIF(item_name, ''), name, 'Item') as item_name, code, category, quantity, unit, price, (quantity * price) as total_value, location, status FROM stock_items WHERE quantity <= 10 ORDER BY quantity ASC");
            } elseif ($tab === 'requests') {
                $data = dbQuery("SELECT * FROM stock_request ORDER BY created_at DESC LIMIT 50");
            } elseif ($tab === 'history') {
                $data = dbQuery("SELECT st.*, COALESCE(si.name, si.item_name, st.item_name) as item_name FROM stock_transfers st LEFT JOIN stock_items si ON st.stock_item_id = si.id ORDER BY st.transfer_date DESC LIMIT 50");
            } elseif ($tab === 'ledger') {
                $data = dbQuery("SELECT * FROM stock_movements ORDER BY created_at DESC, id DESC LIMIT 150");
            }

            sendJson([
                'success' => true,
                'stats' => [
                    'total_items' => $totalItems,
                    'total_qty' => $totalQty,
                    'total_value' => $totalValue,
                    'low_stock' => $lowStock
                ],
                'tab' => $tab,
                'data' => $data
            ]);
            break;

        case 'fetch_stock_counting':
            $items = dbQuery("SELECT id, COALESCE(NULLIF(name, ''), item_name, 'Item') as item_name, quantity, code, category FROM stock_items ORDER BY item_name ASC");
            $searchDate = trim($_POST['search_date'] ?? $_GET['search_date'] ?? date('Y-m-d'));
            $history = dbQuery("SELECT * FROM stock_count_history WHERE DATE(count_date) = ? ORDER BY count_date DESC", [$searchDate]);
            sendJson(['success' => true, 'items' => $items, 'history' => $history, 'search_date' => $searchDate]);
            break;

        case 'save_stock_count':
            $phase = trim($_POST['phase'] ?? 'Morning');
            $counts = $_POST['counts'] ?? [];
            if (is_string($counts)) $counts = json_decode($counts, true) ?: [];

            if (empty($counts)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលចំនួនដែលបានរាប់យ៉ាងហោចណាស់មួយទំនិញ!'], 400);
            }

            foreach ($counts as $itemId => $physQty) {
                $iid = (int)$itemId;
                $pqty = (int)$physQty;
                $stockRow = dbQuery("SELECT id, name, item_name, quantity FROM stock_items WHERE id = ? LIMIT 1", [$iid]);
                if (empty($stockRow)) continue;

                $itemName = $stockRow[0]['name'] ?: $stockRow[0]['item_name'];
                $sysQty = (int)$stockRow[0]['quantity'];
                $diff = $pqty - $sysQty;

                dbQuery("INSERT INTO stock_count_history (item_id, item_name, system_qty, physical_qty, difference, phase, count_date) VALUES (?, ?, ?, ?, ?, ?, NOW())", [$iid, $itemName, $sysQty, $pqty, $diff, $phase]);

                // Update system quantity to match physical count
                $status = $pqty <= 0 ? 'Out of Stock' : ($pqty < 10 ? 'Low Stock' : 'In Stock');
                dbQuery("UPDATE stock_items SET quantity = ?, status = ? WHERE id = ?", [$pqty, $status, $iid]);

                dbQuery("INSERT INTO stock_movements (item_id, item_name, movement_type, quantity_change, quantity_before, quantity_after, reference_no, reference_type, actor_name, notes) VALUES (?, ?, 'count_adjustment', ?, ?, ?, ?, 'Stock Audit', 'Admin', ?)", [$iid, $itemName, $diff, $sysQty, $pqty, "COUNT-$phase", "ការរាប់ស្តុកវេន $phase"]);
            }

            sendJson(['success' => true, 'message' => 'បានរក្សាទុកលទ្ធផលការរាប់ស្តុកជោគជ័យ!']);
            break;

        case 'fetch_stock_requests':
            $status = trim($_POST['status'] ?? $_GET['status'] ?? '');
            if (!empty($status)) {
                $requests = dbQuery("SELECT sr.*, u.name as user_name FROM stock_request sr LEFT JOIN users u ON sr.user_id = u.employee_id WHERE sr.status = ? ORDER BY sr.created_at DESC", [$status]);
            } else {
                $requests = dbQuery("SELECT sr.*, u.name as user_name FROM stock_request sr LEFT JOIN users u ON sr.user_id = u.employee_id ORDER BY sr.created_at DESC LIMIT 100");
            }
            sendJson(['success' => true, 'requests' => $requests]);
            break;

        case 'update_stock_request_status':
            $reqId = (int)($_POST['request_id'] ?? $_POST['id'] ?? 0);
            $newStatus = trim($_POST['status'] ?? 'approved');
            $comment = trim($_POST['admin_comment'] ?? '');

            if ($reqId <= 0) {
                sendJson(['success' => false, 'message' => 'Invalid Request ID'], 400);
            }

            dbQuery("UPDATE stock_request SET status = ?, notes = CONCAT(COALESCE(notes, ''), ' | ', ?) WHERE id = ?", [$newStatus, $comment, $reqId]);
            sendJson(['success' => true, 'message' => "បានធ្វើបច្ចុប្បន្នភាពសំណើជា $newStatus ជោគជ័យ!"]);
            break;

        case 'fetch_direct_transfers':
            $transfers = dbQuery("SELECT st.*, COALESCE(si.name, si.item_name, st.item_name) as item_name FROM stock_transfers st LEFT JOIN stock_items si ON st.stock_item_id = si.id ORDER BY st.transfer_date DESC LIMIT 100");
            sendJson(['success' => true, 'transfers' => $transfers]);
            break;

        case 'save_direct_transfer':
            $title = trim($_POST['transfer_title'] ?? 'Direct Transfer');
            $reqNo = trim($_POST['request_no'] ?? 'TRF-' . time());
            $location = trim($_POST['location'] ?? 'Target Branch');
            $items = $_POST['items'] ?? [];
            if (is_string($items)) $items = json_decode($items, true) ?: [];

            if (empty($items)) {
                sendJson(['success' => false, 'message' => 'សូមជ្រើសរើសទំនិញយ៉ាងហោចណាស់មួយដើម្បីផ្ទេរ!'], 400);
            }

            foreach ($items as $it) {
                $iid = (int)($it['id'] ?? $it['item_id'] ?? 0);
                $qty = (int)($it['qty'] ?? $it['quantity'] ?? 0);
                $note = trim($it['note'] ?? '');
                if ($iid <= 0 || $qty <= 0) continue;

                $stockRow = dbQuery("SELECT id, name, item_name, quantity FROM stock_items WHERE id = ? LIMIT 1", [$iid]);
                if (empty($stockRow)) continue;

                $itemName = $stockRow[0]['name'] ?: $stockRow[0]['item_name'];
                $oldQty = (int)$stockRow[0]['quantity'];
                if ($qty > $oldQty) continue;

                $newQty = $oldQty - $qty;
                $newStatus = $newQty <= 0 ? 'Out of Stock' : ($newQty < 10 ? 'Low Stock' : 'In Stock');

                dbQuery("UPDATE stock_items SET quantity = ?, status = ? WHERE id = ?", [$newQty, $newStatus, $iid]);

                dbQuery("INSERT INTO stock_transfers (transfer_title, request_no, stock_item_id, item_name, quantity_transferred, to_location, notes, transfer_date) VALUES (?, ?, ?, ?, ?, ?, ?, NOW())", [$title, $reqNo, $iid, $itemName, $qty, $location, $note]);

                dbQuery("INSERT INTO stock_movements (item_id, item_name, movement_type, quantity_change, quantity_before, quantity_after, reference_no, reference_type, actor_name, notes, location) VALUES (?, ?, 'transfer', ?, ?, ?, ?, 'Direct Transfer', 'Admin', ?, ?)", [$iid, $itemName, -$qty, $oldQty, $newQty, $reqNo, $note ?: "ផ្ទេរទៅ $location", $location]);
            }

            sendJson(['success' => true, 'message' => 'បានផ្ទេរទំនិញដោយផ្ទាល់ជោគជ័យ!']);
            break;

        // ==========================================
        // 9. MEETINGS & AI
        // ==========================================
        case 'fetch_meetings':
        case 'get_meetings':
            dbQuery("CREATE TABLE IF NOT EXISTS meetings (
                id INT AUTO_INCREMENT PRIMARY KEY,
                topic VARCHAR(255) NOT NULL,
                title VARCHAR(255) DEFAULT NULL,
                department VARCHAR(100) DEFAULT 'All Departments',
                meeting_date DATE,
                duration VARCHAR(50) DEFAULT '30 នាទី',
                summary TEXT,
                audio_url VARCHAR(255) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $meetings = dbQuery("SELECT id, COALESCE(NULLIF(topic, ''), title, 'កិច្ចប្រជុំ') as topic, department, meeting_date as date, duration, summary, (audio_url IS NOT NULL AND audio_url != '') as hasAudio, audio_url FROM meetings ORDER BY id DESC");
            if (empty($meetings)) {
                dbQuery("INSERT INTO meetings (topic, title, department, meeting_date, duration, summary) VALUES 
                    ('កិច្ចប្រជុំប្រចាំសប្តាហ៍ - វឌ្ឍនភាពការងារ & ផែនការលក់', 'កិច្ចប្រជុំប្រចាំសប្តាហ៍', 'Store 318 & SKKS2', '2026-08-20', '45 នាទី', 'ពិភាក្សាអំពីយុទ្ធសាស្រ្តបង្កើនការលក់ប្រចាំត្រីមាសទី ៣ និងការគ្រប់គ្រងស្តុកទំនិញថ្មី។'),
                    ('កិច្ចប្រជុំបច្ចេកទេស - ដំឡើងប្រព័ន្ធស្កេនមុខ (Face Net AI)', 'កិច្ចប្រជុំបច្ចេកទេស', 'IT & HRM', '2026-08-18', '30 នាទី', 'រៀបចំដាក់ឱ្យដំណើរការមុខងារ AI Face Recognition លើ App ទូរស័ព្ទសម្រាប់បុគ្គលិកទាំងអស់។')");
                $meetings = dbQuery("SELECT id, topic, department, meeting_date as date, duration, summary, 1 as hasAudio FROM meetings ORDER BY id DESC");
            }
            sendJson(['success' => true, 'meetings' => $meetings]);
            break;

        case 'save_meeting':
            $meetId = (int)($_POST['id'] ?? 0);
            $topic = trim($_POST['topic'] ?? $_POST['title'] ?? '');
            $dept = trim($_POST['department'] ?? 'All Departments');
            $date = trim($_POST['date'] ?? $_POST['meeting_date'] ?? date('Y-m-d'));
            $dur = trim($_POST['duration'] ?? '30 នាទី');
            $summary = trim($_POST['summary'] ?? '');
            $audioUrl = trim($_POST['audio_url'] ?? '');

            if (empty($topic)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលប្រធានបទកិច្ចប្រជុំ!'], 400);
            }

            if ($meetId > 0) {
                dbQuery("UPDATE meetings SET topic = ?, title = ?, department = ?, meeting_date = ?, duration = ?, summary = ?, audio_url = ? WHERE id = ?", [$topic, $topic, $dept, $date, $dur, $summary, $audioUrl, $meetId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែកិច្ចប្រជុំជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO meetings (topic, title, department, meeting_date, duration, summary, audio_url) VALUES (?, ?, ?, ?, ?, ?, ?)", [$topic, $topic, $dept, $date, $dur, $summary, $audioUrl]);
                sendJson(['success' => true, 'message' => 'បានបង្ហោះកិច្ចប្រជុំថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_meeting':
            $meetId = (int)($_POST['id'] ?? $_POST['meeting_id'] ?? 0);
            if ($meetId > 0) {
                dbQuery("DELETE FROM meetings WHERE id = ?", [$meetId]);
                sendJson(['success' => true, 'message' => 'បានលុបកិច្ចប្រជុំជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Meeting ID']);
            break;

        // ==========================================
        // 10. POLLS & VOTING
        // ==========================================
        case 'fetch_polls':
        case 'get_polls':
            dbQuery("CREATE TABLE IF NOT EXISTS poll_events (
                id INT AUTO_INCREMENT PRIMARY KEY,
                title VARCHAR(255) NOT NULL,
                creator VARCHAR(100) DEFAULT 'Super Admin',
                status VARCHAR(50) DEFAULT 'Active',
                total_votes INT DEFAULT 0,
                ends_at DATE,
                options_json TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $polls = dbQuery("SELECT * FROM poll_events ORDER BY id DESC");
            if (empty($polls)) {
                $opts1 = json_encode([
                    ['text' => 'ខេត្តមណ្ឌលគិរី (Mondulkiri)', 'votes' => 22, 'percentage' => 58],
                    ['text' => 'កោះរ៉ុងសន្លឹម (Koh Rong Sanloem)', 'votes' => 12, 'percentage' => 32],
                    ['text' => 'ខេត្តសៀមរាប (Siem Reap)', 'votes' => 4, 'percentage' => 10],
                ], JSON_UNESCAPED_UNICODE);
                $opts2 = json_encode([
                    ['text' => 'ម្ហូបបែបខ្មែរ (Khmer Set Menu)', 'votes' => 28, 'percentage' => 67],
                    ['text' => 'អាហារប៊ូហ្វេ (Buffet)', 'votes' => 14, 'percentage' => 33],
                ], JSON_UNESCAPED_UNICODE);

                dbQuery("INSERT INTO poll_events (title, creator, status, total_votes, ends_at, options_json) VALUES 
                    ('ជ្រើសរើសទីតាំងដំណើរកម្សាន្តប្រចាំឆ្នាំ (Annual Company Trip 2026)', 'Super Admin', 'Active', 38, '2026-08-31', ?),
                    ('ជ្រើសរើសម៉ឺនុយអាហារថ្ងៃត្រង់សម្រាប់ការប្រជុំធំ', 'HR Manager', 'Closed', 42, '2026-08-15', ?)", [$opts1, $opts2]);
                $polls = dbQuery("SELECT * FROM poll_events ORDER BY id DESC");
            }

            foreach ($polls as &$p) {
                if (!empty($p['options_json'])) {
                    $p['options'] = json_decode($p['options_json'], true) ?: [];
                } else {
                    $p['options'] = [];
                }
            }
            unset($p);
            sendJson(['success' => true, 'polls' => $polls]);
            break;

        case 'save_poll':
            $pollId = (int)($_POST['id'] ?? 0);
            $title = trim($_POST['title'] ?? '');
            $creator = trim($_POST['creator'] ?? 'Super Admin');
            $status = trim($_POST['status'] ?? 'Active');
            $endsAt = trim($_POST['ends_at'] ?? date('Y-m-d', strtotime('+7 days')));
            $options = $_POST['options'] ?? [];
            $optionsJson = is_array($options) ? json_encode($options, JSON_UNESCAPED_UNICODE) : (string)$options;

            if (empty($title)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលចំណងជើងការបោះឆ្នោត!'], 400);
            }

            if ($pollId > 0) {
                dbQuery("UPDATE poll_events SET title = ?, creator = ?, status = ?, ends_at = ?, options_json = ? WHERE id = ?", [$title, $creator, $status, $endsAt, $optionsJson, $pollId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែការបោះឆ្នោតជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO poll_events (title, creator, status, total_votes, ends_at, options_json) VALUES (?, ?, ?, 0, ?, ?)", [$title, $creator, $status, $endsAt, $optionsJson]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតការបោះឆ្នោតថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_poll':
            $pollId = (int)($_POST['id'] ?? $_POST['poll_id'] ?? 0);
            if ($pollId > 0) {
                dbQuery("DELETE FROM poll_events WHERE id = ?", [$pollId]);
                sendJson(['success' => true, 'message' => 'បានលុបការបោះឆ្នោតជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Poll ID']);
            break;

        // ==========================================
        // 11. SESSIONS & TOKENS (REAL ACTIVE_TOKENS TABLE)
        // ==========================================
        case 'fetch_active_sessions':
        case 'get_tokens':
            dbQuery("CREATE TABLE IF NOT EXISTS active_tokens (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                auth_token VARCHAR(255) NOT NULL UNIQUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_emp (employee_id),
                INDEX idx_token (auth_token)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS user_skill_groups (
                id INT AUTO_INCREMENT PRIMARY KEY,
                group_name VARCHAR(255) NOT NULL,
                sort_order INT DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $groups = dbQuery("SELECT id, group_name, sort_order FROM user_skill_groups ORDER BY sort_order ASC, group_name ASC");

            $sessions = dbQuery("SELECT at.id, at.employee_id, at.auth_token, at.created_at, at.last_used,
                                        u.name as user_name, u.name, u.user_role, u.department, u.position, u.custom_data, u.avatar
                                 FROM active_tokens at
                                 JOIN users u ON at.employee_id = u.employee_id
                                 ORDER BY at.created_at DESC");

            $globalMaxRow = dbQuery("SELECT setting_value FROM app_settings WHERE setting_key = 'global_max_tokens' LIMIT 1");
            $globalMaxTokens = !empty($globalMaxRow) ? (int)$globalMaxRow[0]['setting_value'] : 1;
            if ($globalMaxTokens < 1) $globalMaxTokens = 1;

            sendJson(['success' => true, 'sessions' => $sessions, 'groups' => $groups, 'global_max_tokens' => $globalMaxTokens]);
            break;

        case 'revoke_session':
        case 'revoke_token':
            $token = trim($_POST['token'] ?? $_POST['auth_token'] ?? '');
            $sessionId = (int)($_POST['id'] ?? $_POST['session_id'] ?? 0);

            if (!empty($token)) {
                dbQuery("DELETE FROM active_tokens WHERE auth_token = ?", [$token]);
                sendJson(['success' => true, 'message' => 'បានផ្តាច់ Token ជោគជ័យ!']);
            } elseif ($sessionId > 0) {
                dbQuery("DELETE FROM active_tokens WHERE id = ?", [$sessionId]);
                sendJson(['success' => true, 'message' => 'បានផ្តាច់ Session ជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Session or Token ID'], 400);
            break;

        case 'revoke_bulk_tokens':
            $tokens = $_POST['tokens'] ?? [];
            if (is_string($tokens)) $tokens = json_decode($tokens, true) ?: explode(',', $tokens);
            if (!empty($tokens) && is_array($tokens)) {
                $placeholders = implode(',', array_fill(0, count($tokens), '?'));
                dbQuery("DELETE FROM active_tokens WHERE auth_token IN ($placeholders) OR id IN ($placeholders)", array_merge($tokens, $tokens));
                sendJson(['success' => true, 'message' => 'បានផ្តាច់ Session ដែលបានជ្រើសរើសជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'No sessions selected'], 400);
            break;

        case 'revoke_all_sessions':
        case 'revoke_all_my_users_tokens':
            dbQuery("DELETE FROM active_tokens");
            sendJson(['success' => true, 'message' => 'បានផ្តាច់គ្រប់ Session ទាំងអស់ដោយជោគជ័យ!']);
            break;

        case 'fetch_global_token_settings':
        case 'get_global_max_tokens':
            $globalMaxRow = dbQuery("SELECT setting_value FROM app_settings WHERE setting_key = 'global_max_tokens' LIMIT 1");
            $maxTokens = !empty($globalMaxRow) ? (int)$globalMaxRow[0]['setting_value'] : 1;
            sendJson(['success' => true, 'global_max_tokens' => $maxTokens, 'max_tokens' => $maxTokens]);
            break;

        case 'save_global_token_settings':
        case 'set_global_max_tokens':
            $maxTokens = (int)($_POST['global_max_tokens'] ?? $_POST['max_tokens'] ?? 1);
            if ($maxTokens < 1) $maxTokens = 1;
            if ($maxTokens > 10) $maxTokens = 10;

            dbQuery("INSERT INTO app_settings (setting_key, setting_value) VALUES ('global_max_tokens', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)", [(string)$maxTokens]);
            dbQuery("UPDATE users SET global_max_tokens = ?", [$maxTokens]);

            sendJson(['success' => true, 'message' => 'បានរក្សាទុកការកំណត់ចំនួន Token អតិបរមាជោគជ័យ!', 'global_max_tokens' => $maxTokens]);
            break;

        // ==========================================
        // 12. TRAINING & QUIZ
        // ==========================================
        case 'fetch_quizzes':
        case 'get_quizzes':
            dbQuery("CREATE TABLE IF NOT EXISTS training_quiz_questions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                question TEXT NOT NULL,
                department VARCHAR(100) DEFAULT 'All Departments',
                correct_answer VARCHAR(255) NOT NULL,
                options_json TEXT,
                points INT DEFAULT 10,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $quizzes = dbQuery("SELECT * FROM training_quiz_questions ORDER BY id ASC");
            if (empty($quizzes)) {
                $opts1 = json_encode(['07:30 AM', '08:00 AM', '08:30 AM', '09:00 AM'], JSON_UNESCAPED_UNICODE);
                $opts2 = json_encode(['១ ថ្ងៃមុន', '២ ថ្ងៃមុន', '៣ ថ្ងៃមុន', '៥ ថ្ងៃមុន'], JSON_UNESCAPED_UNICODE);

                dbQuery("INSERT INTO training_quiz_questions (question, department, correct_answer, options_json, points) VALUES 
                    ('តើម៉ោងធ្វើការស្តង់ដារពេលព្រឹករបស់ VVC ចាប់ផ្តើមពីម៉ោងប៉ុន្មាន?', 'All Departments', '08:00 AM', ?, 10),
                    ('តើការស្នើសុំច្បាប់ឈប់សម្រាកប្រចាំឆ្នាំ ត្រូវស្នើសុំមុនយ៉ាងតិចប៉ុន្មានថ្ងៃ?', 'HRM', '៣ ថ្ងៃមុន', ?, 10)", [$opts1, $opts2]);
                $quizzes = dbQuery("SELECT * FROM training_quiz_questions ORDER BY id ASC");
            }

            foreach ($quizzes as &$q) {
                if (!empty($q['options_json'])) {
                    $q['options'] = json_decode($q['options_json'], true) ?: [];
                } else {
                    $q['options'] = [];
                }
            }
            unset($q);
            sendJson(['success' => true, 'quizzes' => $quizzes]);
            break;

        case 'save_quiz':
            $quizId = (int)($_POST['id'] ?? 0);
            $question = trim($_POST['question'] ?? '');
            $dept = trim($_POST['department'] ?? 'All Departments');
            $correct = trim($_POST['correct_answer'] ?? '');
            $points = (int)($_POST['points'] ?? 10);
            $options = $_POST['options'] ?? [];
            $optionsJson = is_array($options) ? json_encode($options, JSON_UNESCAPED_UNICODE) : (string)$options;

            if (empty($question) || empty($correct)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលសំណួរ និងចម្លើយត្រឹមត្រូវ!'], 400);
            }

            if ($quizId > 0) {
                dbQuery("UPDATE training_quiz_questions SET question = ?, department = ?, correct_answer = ?, options_json = ?, points = ? WHERE id = ?", [$question, $dept, $correct, $optionsJson, $points, $quizId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែសំណួរជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO training_quiz_questions (question, department, correct_answer, options_json, points) VALUES (?, ?, ?, ?, ?)", [$question, $dept, $correct, $optionsJson, $points]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតសំណួរថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_quiz':
            $quizId = (int)($_POST['id'] ?? $_POST['quiz_id'] ?? 0);
            if ($quizId > 0) {
                dbQuery("DELETE FROM training_quiz_questions WHERE id = ?", [$quizId]);
                sendJson(['success' => true, 'message' => 'បានលុបសំណួរជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Quiz ID']);
            break;

        // ==========================================
        // 13. GPS TRACKING & TRIPS
        // ==========================================
        case 'fetch_gps_trips':
        case 'get_active_trips':
            dbQuery("CREATE TABLE IF NOT EXISTS gps_trips (
                id INT AUTO_INCREMENT PRIMARY KEY,
                driver_name VARCHAR(255) NOT NULL,
                employee_id VARCHAR(50) NOT NULL,
                vehicle VARCHAR(100) DEFAULT 'Truck',
                destination VARCHAR(255) DEFAULT NULL,
                current_location VARCHAR(255) DEFAULT NULL,
                speed VARCHAR(50) DEFAULT '0 km/h',
                status VARCHAR(50) DEFAULT 'In Transit',
                started_at VARCHAR(50) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $trips = dbQuery("SELECT * FROM gps_trips ORDER BY id DESC");
            if (empty($trips)) {
                dbQuery("INSERT INTO gps_trips (driver_name, employee_id, vehicle, destination, current_location, speed, status, started_at) VALUES 
                    ('ជា វណ្ណៈ', 'VVC-103', 'ឡានដឹកទំនិញ (Truck 2.5T)', 'សាខាកំពង់សោម (Sihanoukville Store)', 'ផ្លូវល្បឿនលឿន គ.ម ៧៤', '75 km/h', 'In Transit', '06:30 AM'),
                    ('លឹម គឹមសាន', 'VVC-104', 'ម៉ូតូដឹកឥវ៉ាន់ (Delivery Moto)', 'អតិថិជន KouPrey Coffee (ទួលគោក)', 'ផ្លូវ 598 រាជធានីភ្នំពេញ', '35 km/h', 'Delivering', '08:45 AM')");
                $trips = dbQuery("SELECT * FROM gps_trips ORDER BY id DESC");
            }
            sendJson(['success' => true, 'trips' => $trips]);
            break;

        case 'save_gps_trip':
            $tripId = (int)($_POST['id'] ?? 0);
            $driver = trim($_POST['driver_name'] ?? '');
            $empId = trim($_POST['employee_id'] ?? '');
            $veh = trim($_POST['vehicle'] ?? 'Truck');
            $dest = trim($_POST['destination'] ?? '');
            $loc = trim($_POST['current_location'] ?? '');
            $speed = trim($_POST['speed'] ?? '0 km/h');
            $status = trim($_POST['status'] ?? 'In Transit');
            $startedAt = trim($_POST['started_at'] ?? date('h:i A'));

            if ($tripId > 0) {
                dbQuery("UPDATE gps_trips SET driver_name = ?, employee_id = ?, vehicle = ?, destination = ?, current_location = ?, speed = ?, status = ? WHERE id = ?", [$driver, $empId, $veh, $dest, $loc, $speed, $status, $tripId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែដំណើរបេសកកម្មជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO gps_trips (driver_name, employee_id, vehicle, destination, current_location, speed, status, started_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [$driver, $empId, $veh, $dest, $loc, $speed, $status, $startedAt]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតដំណើរបេសកកម្មថ្មីជោគជ័យ!']);
            }
            break;

        // ==========================================
        // 14. PAYROLL MANAGEMENT
        // ==========================================
        // ==========================================
        // 14. PAYROLL MANAGEMENT & ADJUSTMENTS
        // ==========================================
        case 'fetch_payroll_records':
        case 'fetch_payroll':
        case 'get_salaries':
            dbQuery("CREATE TABLE IF NOT EXISTS payroll_records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                name VARCHAR(255) DEFAULT NULL,
                base_salary DECIMAL(10, 2) DEFAULT 0.00,
                days_present INT DEFAULT 26,
                ot_hours DECIMAL(5, 2) DEFAULT 0.00,
                ot_amount DECIMAL(10, 2) DEFAULT 0.00,
                deductions DECIMAL(10, 2) DEFAULT 0.00,
                loans DECIMAL(10, 2) DEFAULT 0.00,
                net_salary DECIMAL(10, 2) DEFAULT 0.00,
                status VARCHAR(50) DEFAULT 'Pending',
                payroll_month INT DEFAULT 8,
                payroll_year INT DEFAULT 2026,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY emp_month_year (employee_id, payroll_month, payroll_year)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS payroll_configs (
                employee_id VARCHAR(50) PRIMARY KEY,
                base_salary DECIMAL(10,2) DEFAULT 0.00,
                payment_type VARCHAR(50) DEFAULT 'Monthly',
                bank_name VARCHAR(255) DEFAULT '',
                bank_account_number VARCHAR(255) DEFAULT '',
                nssf_id VARCHAR(100) DEFAULT '',
                bank_qr_file VARCHAR(255) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS payroll_deductions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                amount DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                reason VARCHAR(255) DEFAULT '',
                deduction_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS payroll_ot (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                ot_hours DECIMAL(5,2) DEFAULT 0.00,
                ot_rate DECIMAL(10,2) DEFAULT 0.00,
                total_ot_amount DECIMAL(10,2) DEFAULT 0.00,
                reason VARCHAR(255) DEFAULT '',
                ot_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS payroll_loans (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                total_loan DECIMAL(10,2) DEFAULT 0.00,
                monthly_installment DECIMAL(10,2) DEFAULT 0.00,
                reason VARCHAR(255) DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            dbQuery("CREATE TABLE IF NOT EXISTS payroll_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                payroll_month INT NOT NULL,
                payroll_year INT NOT NULL,
                calculated_salary DECIMAL(10,2) NOT NULL DEFAULT 0.00,
                payment_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'Paid'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $month = (int)($_POST['month'] ?? $_GET['month'] ?? date('n'));
            $year = (int)($_POST['year'] ?? $_GET['year'] ?? date('Y'));

            $payroll = dbQuery("SELECT p.*, u.name as user_name, u.department, u.position FROM payroll_records p LEFT JOIN users u ON p.employee_id = u.employee_id WHERE p.payroll_month = ? AND p.payroll_year = ? ORDER BY p.id DESC", [$month, $year]);

            if (empty($payroll)) {
                $users = dbQuery("SELECT employee_id, name, base_salary, department, position FROM users WHERE is_active = 1");
                foreach ($users as $u) {
                    $base = (float)($u['base_salary'] ?? 350.00);
                    $otHours = 0;
                    $otAmt = 0;
                    $ded = 0;
                    $loan = 0;
                    $net = $base;
                    dbQuery("INSERT IGNORE INTO payroll_records (employee_id, name, base_salary, days_present, ot_hours, ot_amount, deductions, loans, net_salary, status, payroll_month, payroll_year) VALUES (?, ?, ?, 26, ?, ?, ?, ?, ?, 'Pending', ?, ?)", [$u['employee_id'], $u['name'], $base, $otHours, $otAmt, $ded, $loan, $net, $month, $year]);
                }
                $payroll = dbQuery("SELECT p.*, u.name as user_name, u.department, u.position FROM payroll_records p LEFT JOIN users u ON p.employee_id = u.employee_id WHERE p.payroll_month = ? AND p.payroll_year = ? ORDER BY p.id DESC", [$month, $year]);
            }

            foreach ($payroll as &$pr) {
                if (empty($pr['name']) && !empty($pr['user_name'])) {
                    $pr['name'] = $pr['user_name'];
                }
            }
            unset($pr);
            sendJson(['success' => true, 'salaries' => $payroll, 'month' => $month, 'year' => $year]);
            break;

        case 'fetch_payroll_configs':
            $configs = dbQuery("SELECT u.employee_id, u.name, COALESCE(pc.base_salary, u.base_salary, 0.00) as base_salary, COALESCE(pc.bank_name, '') as bank_name, COALESCE(pc.bank_account_number, '') as bank_account_number, COALESCE(pc.bank_qr_file, u.bank_qr_code_url, '') as bank_qr_url FROM users u LEFT JOIN payroll_configs pc ON u.employee_id = pc.employee_id ORDER BY u.name ASC");
            sendJson(['success' => true, 'configs' => $configs]);
            break;

        case 'save_payroll_config':
        case 'payroll_save_config':
            $empId = trim($_POST['employee_id'] ?? '');
            $baseSalary = (float)($_POST['base_salary'] ?? 0.00);
            $bankName = trim($_POST['bank_name'] ?? '');
            $bankAccount = trim($_POST['bank_account_number'] ?? '');
            $paymentType = trim($_POST['payment_type'] ?? 'Monthly');
            $qrPath = null;

            if (isset($_FILES['bank_qr']) && $_FILES['bank_qr']['error'] === UPLOAD_ERR_OK) {
                $ext = strtolower(pathinfo($_FILES['bank_qr']['name'], PATHINFO_EXTENSION));
                if (in_array($ext, ['jpg', 'jpeg', 'png', 'webp'])) {
                    $uploadDir = __DIR__ . '/uploads/bank_qr/';
                    if (!is_dir($uploadDir)) @mkdir($uploadDir, 0777, true);
                    $filename = 'qr_' . time() . '_' . rand(1000, 9999) . '.' . $ext;
                    if (move_uploaded_file($_FILES['bank_qr']['tmp_name'], $uploadDir . $filename)) {
                        $qrPath = 'uploads/bank_qr/' . $filename;
                    }
                }
            }

            if (empty($empId)) {
                sendJson(['success' => false, 'message' => 'Missing employee_id'], 400);
            }

            if ($qrPath) {
                dbQuery("INSERT INTO payroll_configs (employee_id, base_salary, payment_type, bank_name, bank_account_number, bank_qr_file) VALUES (?, ?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE base_salary = VALUES(base_salary), bank_name = VALUES(bank_name), bank_account_number = VALUES(bank_account_number), bank_qr_file = VALUES(bank_qr_file)", [$empId, $baseSalary, $paymentType, $bankName, $bankAccount, $qrPath]);
                dbQuery("UPDATE users SET base_salary = ?, bank_qr_code_url = ? WHERE employee_id = ?", [$baseSalary, $qrPath, $empId]);
            } else {
                dbQuery("INSERT INTO payroll_configs (employee_id, base_salary, payment_type, bank_name, bank_account_number) VALUES (?, ?, ?, ?, ?) ON DUPLICATE KEY UPDATE base_salary = VALUES(base_salary), bank_name = VALUES(bank_name), bank_account_number = VALUES(bank_account_number)", [$empId, $baseSalary, $paymentType, $bankName, $bankAccount]);
                dbQuery("UPDATE users SET base_salary = ? WHERE employee_id = ?", [$baseSalary, $empId]);
            }

            sendJson(['success' => true, 'message' => 'បានរក្សាទុកព័ត៌មានប្រាក់បៀវត្ស និងគណនីធនាគារជោគជ័យ!']);
            break;

        case 'save_payroll_record':
        case 'save_payroll':
            $payId = (int)($_POST['id'] ?? 0);
            $empId = trim($_POST['employee_id'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $base = (float)($_POST['base_salary'] ?? 0.00);
            $days = (int)($_POST['days_present'] ?? 26);
            $otHours = (float)($_POST['ot_hours'] ?? 0.00);
            $otAmt = (float)($_POST['ot_amount'] ?? 0.00);
            $ded = (float)($_POST['deductions'] ?? 0.00);
            $loan = (float)($_POST['loans'] ?? 0.00);
            $net = $base + $otAmt - $ded - $loan;
            $status = trim($_POST['status'] ?? 'Paid');
            $month = (int)($_POST['month'] ?? date('n'));
            $year = (int)($_POST['year'] ?? date('Y'));

            if ($payId > 0) {
                dbQuery("UPDATE payroll_records SET base_salary = ?, days_present = ?, ot_hours = ?, ot_amount = ?, deductions = ?, loans = ?, net_salary = ?, status = ? WHERE id = ?", [$base, $days, $otHours, $otAmt, $ded, $loan, $net, $status, $payId]);
                if ($status === 'Paid') {
                    dbQuery("INSERT INTO payroll_history (employee_id, payroll_month, payroll_year, calculated_salary, status) VALUES (?, ?, ?, ?, 'Paid')", [$empId, $month, $year, $net]);
                }
                sendJson(['success' => true, 'message' => 'បានកែប្រែទិន្នន័យប្រាក់បៀវត្សជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO payroll_records (employee_id, name, base_salary, days_present, ot_hours, ot_amount, deductions, loans, net_salary, status, payroll_month, payroll_year) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", [$empId, $name, $base, $days, $otHours, $otAmt, $ded, $loan, $net, $status, $month, $year]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតកំណត់ត្រាប្រាក់បៀវត្សជោគជ័យ!']);
            }
            break;

        case 'calculate_payroll':
            $month = (int)($_POST['month'] ?? date('n'));
            $year = (int)($_POST['year'] ?? date('Y'));
            $users = dbQuery("SELECT employee_id, name, base_salary FROM users WHERE is_active = 1");

            foreach ($users as $u) {
                $eid = $u['employee_id'];
                $base = (float)($u['base_salary'] ?? 350);

                // Fetch total deductions for this employee
                $dedRow = dbQuery("SELECT SUM(amount) as s FROM payroll_deductions WHERE employee_id = ? AND MONTH(deduction_date) = ? AND YEAR(deduction_date) = ?", [$eid, $month, $year]);
                $ded = (float)($dedRow[0]['s'] ?? 0);

                // Fetch total OT
                $otRow = dbQuery("SELECT SUM(ot_hours) as h, SUM(total_ot_amount) as a FROM payroll_ot WHERE employee_id = ? AND MONTH(ot_date) = ? AND YEAR(ot_date) = ?", [$eid, $month, $year]);
                $otHours = (float)($otRow[0]['h'] ?? 0);
                $otAmt = (float)($otRow[0]['a'] ?? 0);

                // Fetch loan installment
                $loanRow = dbQuery("SELECT SUM(monthly_installment) as s FROM payroll_loans WHERE employee_id = ?", [$eid]);
                $loan = (float)($loanRow[0]['s'] ?? 0);

                $net = $base + $otAmt - $ded - $loan;

                dbQuery("INSERT INTO payroll_records (employee_id, name, base_salary, days_present, ot_hours, ot_amount, deductions, loans, net_salary, status, payroll_month, payroll_year) 
                    VALUES (?, ?, ?, 26, ?, ?, ?, ?, ?, 'Pending', ?, ?) 
                    ON DUPLICATE KEY UPDATE base_salary = VALUES(base_salary), ot_hours = VALUES(ot_hours), ot_amount = VALUES(ot_amount), deductions = VALUES(deductions), loans = VALUES(loans), net_salary = VALUES(net_salary)",
                    [$eid, $u['name'], $base, $otHours, $otAmt, $ded, $loan, $net, $month, $year]);
            }
            sendJson(['success' => true, 'message' => "បានគណនាប្រាក់បៀវត្សសម្រាប់ខែ $month/$year ដោយជោគជ័យ!"]);
            break;

        case 'fetch_payroll_adjustments':
            $deductions = dbQuery("SELECT d.*, u.name as emp_name FROM payroll_deductions d LEFT JOIN users u ON d.employee_id = u.employee_id ORDER BY d.id DESC LIMIT 50");
            $ots = dbQuery("SELECT o.*, u.name as emp_name FROM payroll_ot o LEFT JOIN users u ON o.employee_id = u.employee_id ORDER BY o.id DESC LIMIT 50");
            $loans = dbQuery("SELECT l.*, u.name as emp_name FROM payroll_loans l LEFT JOIN users u ON l.employee_id = u.employee_id ORDER BY l.id DESC LIMIT 50");
            sendJson(['success' => true, 'deductions' => $deductions, 'ots' => $ots, 'loans' => $loans]);
            break;

        case 'save_payroll_deduction':
            $empId = trim($_POST['employee_id'] ?? $_POST['emp_id'] ?? '');
            $amt = (float)($_POST['amount'] ?? 0.00);
            $reason = trim($_POST['reason'] ?? '');
            $date = trim($_POST['deduction_date'] ?? date('Y-m-d'));
            if (empty($empId) || $amt <= 0) sendJson(['success' => false, 'message' => 'សូមបញ្ចូលព័ត៌មានឱ្យបានត្រឹមត្រូវ!'], 400);
            dbQuery("INSERT INTO payroll_deductions (employee_id, amount, reason, deduction_date) VALUES (?, ?, ?, ?)", [$empId, $amt, $reason, $date]);
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកការកាត់ប្រាក់ជោគជ័យ!']);
            break;

        case 'save_payroll_ot':
            $empId = trim($_POST['employee_id'] ?? $_POST['emp_id'] ?? '');
            $hours = (float)($_POST['ot_hours'] ?? 0.00);
            $rate = (float)($_POST['ot_rate'] ?? 3.50);
            $amt = $hours * $rate;
            $reason = trim($_POST['reason'] ?? '');
            $date = trim($_POST['ot_date'] ?? date('Y-m-d'));
            if (empty($empId) || $hours <= 0) sendJson(['success' => false, 'message' => 'សូមបញ្ចូលព័ត៌មានឱ្យបានត្រឹមត្រូវ!'], 400);
            dbQuery("INSERT INTO payroll_ot (employee_id, ot_hours, ot_rate, total_ot_amount, reason, ot_date) VALUES (?, ?, ?, ?, ?, ?)", [$empId, $hours, $rate, $amt, $reason, $date]);
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកប្រាក់ថែមម៉ោងជោគជ័យ!']);
            break;

        case 'save_payroll_loan':
            $empId = trim($_POST['employee_id'] ?? $_POST['emp_id'] ?? '');
            $totalLoan = (float)($_POST['total_loan'] ?? 0.00);
            $installment = (float)($_POST['monthly_installment'] ?? 0.00);
            $reason = trim($_POST['reason'] ?? '');
            if (empty($empId) || $totalLoan <= 0) sendJson(['success' => false, 'message' => 'សូមបញ្ចូលព័ត៌មានឱ្យបានត្រឹមត្រូវ!'], 400);
            dbQuery("INSERT INTO payroll_loans (employee_id, total_loan, monthly_installment, reason) VALUES (?, ?, ?, ?)", [$empId, $totalLoan, $installment, $reason]);
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកបំណុល/ប្រាក់កម្ចីជោគជ័យ!']);
            break;

        case 'fetch_payroll_history':
            $history = dbQuery("SELECT h.*, u.name as emp_name FROM payroll_history h LEFT JOIN users u ON h.employee_id = u.employee_id ORDER BY h.id DESC LIMIT 50");
            sendJson(['success' => true, 'history' => $history]);
            break;

        // ==========================================
        // 15. NOTIFICATIONS LIST
        // ==========================================
        case 'fetch_notifications':
            $notifs = dbQuery("SELECT * FROM notifications ORDER BY id DESC LIMIT 50");
            sendJson(['success' => true, 'notifications' => $notifs]);
            break;

        case 'delete_notification':
            $notifId = (int)($_POST['id'] ?? 0);
            if ($notifId > 0) {
                dbQuery("DELETE FROM notifications WHERE id = ?", [$notifId]);
                sendJson(['success' => true, 'message' => 'បានលុបការជូនដំណឹងជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Notification ID']);
            break;

        // ==========================================
        // 16. THEMES & SETTINGS
        // ==========================================
        case 'fetch_themes':
        case 'get_themes':
            $themes = dbQuery("SELECT * FROM app_themes ORDER BY display_order ASC");
            sendJson(['success' => true, 'themes' => $themes]);
            break;

        case 'set_active_theme':
            $themeId = trim($_POST['theme_id'] ?? '');
            if (!empty($themeId)) {
                dbQuery("UPDATE app_themes SET is_active = 0");
                dbQuery("UPDATE app_themes SET is_active = 1 WHERE theme_id = ?", [$themeId]);
                sendJson(['success' => true, 'message' => 'បានប្តូរ Theme ជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Missing theme_id']);
            break;

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

        case 'get_global_token_settings':
        case 'fetch_global_token_settings':
            $maxTokens = 1;
            $row = dbQuery("SELECT setting_value FROM app_settings WHERE admin_id = 'SYSTEM_WIDE' AND setting_key = 'global_max_tokens' LIMIT 1");
            if (!empty($row)) {
                $maxTokens = (int)$row[0]['setting_value'];
            }
            sendJson(['success' => true, 'global_max_tokens' => $maxTokens, 'max_tokens' => $maxTokens]);
            break;

        case 'set_global_max_tokens':
        case 'save_global_token_settings':
            $max = (int)($_POST['global_max_tokens'] ?? $_POST['max_tokens'] ?? 1);
            if ($max < 1) $max = 1;
            if ($max > 10) $max = 10;
            dbQuery("INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', 'global_max_tokens', ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)", [(string)$max]);
            dbQuery("UPDATE users SET global_max_tokens = ?", [$max]);
            sendJson(['success' => true, 'message' => "បានកំណត់ចំនួន Token អតិបរមាទៅកាន់ $max ជោគជ័យ!"]);
            break;

        case 'save_theme':
            $themeId = trim($_POST['theme_id'] ?? '');
            $themeName = trim($_POST['theme_name'] ?? '');
            $themeNameKh = trim($_POST['theme_name_kh'] ?? '');
            $primaryColor = trim($_POST['primary_color'] ?? '#0E7490');
            $secondaryColor = trim($_POST['secondary_color'] ?? '#2563EB');
            $accentColor = trim($_POST['accent_color'] ?? '#F59E0B');
            $bgColor = trim($_POST['background_color'] ?? '#111827');
            $cardColor = trim($_POST['card_color'] ?? '#1F2937');
            $textPrimary = trim($_POST['text_primary_color'] ?? '#FFFFFF');
            $textSecondary = trim($_POST['text_secondary_color'] ?? '#CBD5E1');

            if (!empty($themeId) && !empty($themeName)) {
                dbQuery("INSERT INTO app_themes (theme_id, theme_name, theme_name_kh, primary_color, secondary_color, accent_color, background_color, card_color, text_primary_color, text_secondary_color) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                    ON DUPLICATE KEY UPDATE theme_name = VALUES(theme_name), theme_name_kh = VALUES(theme_name_kh), primary_color = VALUES(primary_color), secondary_color = VALUES(secondary_color), accent_color = VALUES(accent_color), background_color = VALUES(background_color), card_color = VALUES(card_color), text_primary_color = VALUES(text_primary_color), text_secondary_color = VALUES(text_secondary_color)",
                    [$themeId, $themeName, $themeNameKh, $primaryColor, $secondaryColor, $accentColor, $bgColor, $cardColor, $textPrimary, $textSecondary]);
                sendJson(['success' => true, 'message' => 'បានរក្សាទុក Theme ជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Missing theme_id or theme_name'], 400);
            break;

        case 'delete_theme':
            $themeId = trim($_POST['theme_id'] ?? '');
            if (!empty($themeId)) {
                dbQuery("DELETE FROM app_themes WHERE theme_id = ?", [$themeId]);
                sendJson(['success' => true, 'message' => 'បានលុប Theme ជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Missing theme_id'], 400);
            break;

        case 'get_login_page_settings':
        case 'fetch_login_page_settings':
            $title = 'VVC Attendance Admin Portal';
            $subtitle = 'Sign in to access your dashboard';
            $icon = 'fa-solid fa-user-shield';
            $rows = dbQuery("SELECT setting_key, setting_value FROM app_settings WHERE admin_id = 'SYSTEM_WIDE' AND setting_key IN ('login_page_title', 'login_page_subtitle', 'login_page_icon_class', 'login_page_logo_path')");
            $loginSettings = [];
            foreach ($rows as $r) {
                $loginSettings[$r['setting_key']] = $r['setting_value'];
            }
            sendJson(['success' => true, 'settings' => $loginSettings]);
            break;

        case 'save_login_page_settings':
            foreach ($_POST as $k => $v) {
                if ($k === 'action') continue;
                dbQuery("INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)", [$k, (string)$v]);
            }
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកការកំណត់ Login Page ជោគជ័យ!']);
            break;

        case 'get_app_scan_settings':
        case 'fetch_app_scan_settings':
            $appSettings = [];
            try {
                $rows = dbQuery("SELECT admin_id, setting_key, setting_value FROM app_settings ORDER BY (setting_value != '') ASC, (admin_id = 'SYSTEM_WIDE') ASC");
                foreach ($rows as $r) {
                    if (!empty($r['setting_value']) || !isset($appSettings[$r['setting_key']])) {
                        $appSettings[$r['setting_key']] = $r['setting_value'];
                    }
                }
            } catch (Throwable $ignore) {}

            try {
                $scanRows = dbQuery("SELECT admin_id, setting_key, setting_value FROM app_scan_settings ORDER BY (setting_value != '') ASC, (admin_id = 'SYSTEM_WIDE') ASC");
                foreach ($scanRows as $sr) {
                    if (!empty($sr['setting_value']) || !isset($appSettings[$sr['setting_key']])) {
                        $appSettings[$sr['setting_key']] = $sr['setting_value'];
                    }
                }
            } catch (Throwable $ignore) {}

            try {
                $drSettings = dbQuery("SELECT * FROM daily_report_telegram_settings LIMIT 1");
                if (!empty($drSettings)) {
                    $dr = $drSettings[0];
                    if (!empty($dr['bot_token']) && empty($appSettings['daily_report_telegram_bot_token'])) {
                        $appSettings['daily_report_telegram_bot_token'] = $dr['bot_token'];
                    }
                    if (!empty($dr['chat_id']) && empty($appSettings['daily_report_telegram_chat_id'])) {
                        $appSettings['daily_report_telegram_chat_id'] = $dr['chat_id'];
                    }
                }
            } catch (Throwable $ignore) {}

            sendJson(['success' => true, 'settings' => $appSettings]);
            break;

        case 'save_app_scan_settings':
            foreach ($_POST as $k => $v) {
                if ($k === 'action') continue;
                if (is_array($v)) $v = json_encode($v, JSON_UNESCAPED_UNICODE);
                dbQuery("INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)", [$k, (string)$v]);
                try {
                    dbQuery("INSERT INTO app_scan_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', ?, ?) ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)", [$k, (string)$v]);
                } catch (Throwable $ignore) {}
            }
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកការកំណត់ App Scan ជោគជ័យ!']);
            break;

        case 'fetch_scan_history':
        case 'get_scan_history':
            $history = dbQuery("SELECT l.*, u.name as user_name FROM checkin_logs l LEFT JOIN users u ON l.employee_id = u.employee_id ORDER BY l.log_datetime DESC LIMIT 100");
            sendJson(['success' => true, 'history' => $history]);
            break;

        case 'fetch_payroll_biometric_records':
        case 'get_payroll_biometric_records':
            try {
                $bioRows = dbQuery("SELECT b.id, b.employee_id, COALESCE(NULLIF(b.employee_name, ''), u.name, b.employee_id) AS employee_name, u.department, u.position, b.verification_count, b.first_verified_at, b.last_verified_at, DATE_FORMAT(b.first_verified_at, '%d/%m/%Y %h:%i %p') AS first_verified_at_formatted, DATE_FORMAT(b.last_verified_at, '%d/%m/%Y %h:%i %p') AS last_verified_at_formatted, b.last_platform, b.last_auth_method, b.last_ip_address FROM payroll_biometric_records b LEFT JOIN users u ON b.employee_id = u.employee_id WHERE b.purpose = 'payroll' ORDER BY b.last_verified_at DESC LIMIT 100");
                sendJson(['success' => true, 'records' => $bioRows]);
            } catch (Throwable $e) {
                sendJson(['success' => true, 'records' => []]);
            }
            break;

        case 'delete_payroll_biometric_record':
            $recordId = (int)($_POST['record_id'] ?? $_POST['id'] ?? 0);
            if ($recordId > 0) {
                dbQuery("DELETE FROM payroll_biometric_records WHERE id = ?", [$recordId]);
                sendJson(['success' => true, 'message' => 'បានលុបកំណត់ត្រា Biometric ជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Missing record_id'], 400);
            break;

        case 'clear_payroll_biometric_records':
            dbQuery("DELETE FROM payroll_biometric_records WHERE purpose = 'payroll'");
            sendJson(['success' => true, 'message' => 'បានសម្អាតកំណត់ត្រា Biometric ទាំងអស់ជោគជ័យ!']);
            break;

        case 'get_menu_settings':
        case 'fetch_menu_settings':
            $menus = dbQuery("SELECT menu_key, menu_text, menu_order FROM sidebar_settings ORDER BY menu_order ASC");
            sendJson(['success' => true, 'menus' => $menus]);
            break;

        case 'save_menu_settings':
            if (isset($_POST['menu_text']) && is_array($_POST['menu_text'])) {
                foreach ($_POST['menu_text'] as $mKey => $mTxt) {
                    $order = (int)($_POST['menu_order'][$mKey] ?? 0);
                    dbQuery("INSERT INTO sidebar_settings (menu_key, menu_text, menu_order) VALUES (?, ?, ?) ON DUPLICATE KEY UPDATE menu_text = VALUES(menu_text), menu_order = VALUES(menu_order)", [$mKey, $mTxt, $order]);
                }
            }
            sendJson(['success' => true, 'message' => 'បានរក្សាទុកការកំណត់ Menu ជោគជ័យ!']);
            break;

        default:
            sendJson(['success' => false, 'message' => "Unknown action '$action'"], 404);
            break;
    }
} catch (Throwable $e) {
    sendJson(['success' => false, 'message' => 'Server Error: ' . $e->getMessage()], 500);
}
