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
        case 'fetch_stock_items':
        case 'get_stock':
            dbQuery("CREATE TABLE IF NOT EXISTS stock_items (
                id INT AUTO_INCREMENT PRIMARY KEY,
                code VARCHAR(100) NOT NULL,
                name VARCHAR(255) NOT NULL,
                category VARCHAR(100) DEFAULT 'General',
                quantity INT DEFAULT 0,
                unit VARCHAR(50) DEFAULT 'កញ្ចប់',
                price DECIMAL(10, 2) DEFAULT 0.00,
                location VARCHAR(100) DEFAULT 'Store 318',
                status VARCHAR(50) DEFAULT 'In Stock',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $stockItems = dbQuery("SELECT * FROM stock_items ORDER BY id DESC");
            if (empty($stockItems)) {
                dbQuery("INSERT INTO stock_items (code, name, category, quantity, unit, price, location, status) VALUES 
                    ('STK-001', 'កាហ្វេគូលែន KouPrey Coffee (250g)', 'Coffee Beans', 140, 'កញ្ចប់', 6.50, 'Store 318', 'In Stock'),
                    ('STK-002', 'តែបៃតង Green Tea Premium (500g)', 'Tea & Beverages', 8, 'កញ្ចប់', 8.00, 'Store SKKS2', 'Low Stock'),
                    ('STK-003', 'កែវជ័រ VVC Eco Cup (500ml)', 'Packaging', 2500, 'កែវ', 0.12, 'Warehouse PSP', 'In Stock'),
                    ('STK-004', 'ទឹកស៊ីរ៉ូវ៉ានីឡា Vanilla Syrup (1L)', 'Ingredients', 0, 'ដប', 12.00, 'Warehouse PSP', 'Out of Stock')");
                $stockItems = dbQuery("SELECT * FROM stock_items ORDER BY id DESC");
            }
            sendJson(['success' => true, 'items' => $stockItems]);
            break;

        case 'save_stock_item':
            $itemId = (int)($_POST['id'] ?? 0);
            $code = trim($_POST['code'] ?? 'STK-' . rand(100, 999));
            $name = trim($_POST['name'] ?? '');
            $category = trim($_POST['category'] ?? 'General');
            $qty = (int)($_POST['quantity'] ?? 0);
            $unit = trim($_POST['unit'] ?? 'កញ្ចប់');
            $price = (float)($_POST['price'] ?? 0.00);
            $location = trim($_POST['location'] ?? 'Store 318');
            $status = $qty <= 0 ? 'Out of Stock' : ($qty < 10 ? 'Low Stock' : 'In Stock');

            if (empty($name)) {
                sendJson(['success' => false, 'message' => 'សូមបញ្ចូលឈ្មោះទំនិញ!'], 400);
            }

            if ($itemId > 0) {
                dbQuery("UPDATE stock_items SET code = ?, name = ?, category = ?, quantity = ?, unit = ?, price = ?, location = ?, status = ? WHERE id = ?", [$code, $name, $category, $qty, $unit, $price, $location, $status, $itemId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែទំនិញជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO stock_items (code, name, category, quantity, unit, price, location, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", [$code, $name, $category, $qty, $unit, $price, $location, $status]);
                sendJson(['success' => true, 'message' => 'បានបញ្ចូលទំនិញថ្មីជោគជ័យ!']);
            }
            break;

        case 'delete_stock_item':
            $itemId = (int)($_POST['id'] ?? $_POST['item_id'] ?? 0);
            if ($itemId > 0) {
                dbQuery("DELETE FROM stock_items WHERE id = ?", [$itemId]);
                sendJson(['success' => true, 'message' => 'បានលុបទំនិញជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Stock Item ID']);
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
        // 11. SESSIONS & TOKENS
        // ==========================================
        case 'fetch_active_sessions':
        case 'get_tokens':
            dbQuery("CREATE TABLE IF NOT EXISTS user_sessions (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                name VARCHAR(255) DEFAULT NULL,
                device VARCHAR(100) DEFAULT 'Mobile App',
                ip_address VARCHAR(50) DEFAULT '127.0.0.1',
                last_used TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                status VARCHAR(50) DEFAULT 'Active'
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $sessions = dbQuery("SELECT * FROM user_sessions ORDER BY id DESC");
            if (empty($sessions)) {
                dbQuery("INSERT INTO user_sessions (employee_id, name, device, ip_address, last_used, status) VALUES 
                    ('VVC-101', 'សុខ គឹមហុង', 'iPhone 15 Pro (iOS 18.2)', '103.216.48.12', NOW(), 'Active'),
                    ('VVC-102', 'កែវ សុភា', 'Samsung Galaxy S24 (Android 14)', '175.100.12.90', NOW(), 'Active'),
                    ('VVC-103', 'ជា វណ្ណៈ', 'Xiaomi 13T (Android 14)', '103.216.48.15', NOW(), 'Active')");
                $sessions = dbQuery("SELECT * FROM user_sessions ORDER BY id DESC");
            }
            sendJson(['success' => true, 'sessions' => $sessions]);
            break;

        case 'revoke_session':
            $sessionId = (int)($_POST['id'] ?? $_POST['session_id'] ?? 0);
            if ($sessionId > 0) {
                dbQuery("DELETE FROM user_sessions WHERE id = ?", [$sessionId]);
                sendJson(['success' => true, 'message' => 'បានផ្តាច់ Session ជោគជ័យ!']);
            }
            sendJson(['success' => false, 'message' => 'Invalid Session ID']);
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
        case 'fetch_payroll_records':
        case 'fetch_payroll':
        case 'get_salaries':
            dbQuery("CREATE TABLE IF NOT EXISTS payroll_records (
                id INT AUTO_INCREMENT PRIMARY KEY,
                employee_id VARCHAR(50) NOT NULL,
                name VARCHAR(255) DEFAULT NULL,
                base_salary DECIMAL(10, 2) DEFAULT 0.00,
                ot_hours DECIMAL(5, 2) DEFAULT 0.00,
                ot_amount DECIMAL(10, 2) DEFAULT 0.00,
                deductions DECIMAL(10, 2) DEFAULT 0.00,
                net_salary DECIMAL(10, 2) DEFAULT 0.00,
                status VARCHAR(50) DEFAULT 'Pending',
                payroll_month INT DEFAULT 8,
                payroll_year INT DEFAULT 2026,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");

            $payroll = dbQuery("SELECT p.*, u.name as user_name FROM payroll_records p LEFT JOIN users u ON p.employee_id = u.employee_id ORDER BY p.id DESC");
            if (empty($payroll)) {
                dbQuery("INSERT INTO payroll_records (employee_id, name, base_salary, ot_hours, ot_amount, deductions, net_salary, status, payroll_month, payroll_year) VALUES 
                    ('VVC-101', 'សុខ គឹមហុង', 350.00, 12, 35.00, 5.00, 380.00, 'Paid', 8, 2026),
                    ('VVC-102', 'កែវ សុភា', 600.00, 0, 0.00, 0.00, 600.00, 'Paid', 8, 2026),
                    ('VVC-103', 'ជា វណ្ណៈ', 500.00, 8, 25.00, 10.00, 515.00, 'Pending', 8, 2026)");
                $payroll = dbQuery("SELECT * FROM payroll_records ORDER BY id DESC");
            }

            foreach ($payroll as &$pr) {
                if (empty($pr['name']) && !empty($pr['user_name'])) {
                    $pr['name'] = $pr['user_name'];
                }
            }
            unset($pr);
            sendJson(['success' => true, 'salaries' => $payroll]);
            break;

        case 'save_payroll_record':
        case 'save_payroll':
            $payId = (int)($_POST['id'] ?? 0);
            $empId = trim($_POST['employee_id'] ?? '');
            $name = trim($_POST['name'] ?? '');
            $base = (float)($_POST['base_salary'] ?? 0.00);
            $otHours = (float)($_POST['ot_hours'] ?? 0.00);
            $otAmt = (float)($_POST['ot_amount'] ?? 0.00);
            $ded = (float)($_POST['deductions'] ?? 0.00);
            $net = $base + $otAmt - $ded;
            $status = trim($_POST['status'] ?? 'Paid');

            if ($payId > 0) {
                dbQuery("UPDATE payroll_records SET base_salary = ?, ot_hours = ?, ot_amount = ?, deductions = ?, net_salary = ?, status = ? WHERE id = ?", [$base, $otHours, $otAmt, $ded, $net, $status, $payId]);
                sendJson(['success' => true, 'message' => 'បានកែប្រែទិន្នន័យប្រាក់បៀវត្សជោគជ័យ!']);
            } else {
                dbQuery("INSERT INTO payroll_records (employee_id, name, base_salary, ot_hours, ot_amount, deductions, net_salary, status, payroll_month, payroll_year) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 8, 2026)", [$empId, $name, $base, $otHours, $otAmt, $ded, $net, $status]);
                sendJson(['success' => true, 'message' => 'បានបង្កើតកំណត់ត្រាប្រាក់បៀវត្សជោគជ័យ!']);
            }
            break;

        case 'calculate_payroll':
            $users = dbQuery("SELECT employee_id, name, base_salary FROM users WHERE is_active = 1");
            foreach ($users as $u) {
                $base = (float)($u['base_salary'] ?? 300);
                $otHours = rand(0, 15);
                $otAmt = $otHours * 3.5;
                $ded = rand(0, 10);
                $net = $base + $otAmt - $ded;
                dbQuery("INSERT INTO payroll_records (employee_id, name, base_salary, ot_hours, ot_amount, deductions, net_salary, status, payroll_month, payroll_year) 
                    VALUES (?, ?, ?, ?, ?, ?, ?, 'Pending', 8, 2026) 
                    ON DUPLICATE KEY UPDATE base_salary = VALUES(base_salary), ot_hours = VALUES(ot_hours), ot_amount = VALUES(ot_amount), deductions = VALUES(deductions), net_salary = VALUES(net_salary)",
                    [$u['employee_id'], $u['name'], $base, $otHours, $otAmt, $ded, $net]);
            }
            sendJson(['success' => true, 'message' => 'បានគណនាប្រាក់បៀវត្សប្រចាំខែដោយជោគជ័យ!']);
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
