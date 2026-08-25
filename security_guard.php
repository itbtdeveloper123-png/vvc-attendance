<?php
/**
 * VVC Attendance & HRM - Security Guard Web Application Firewall (WAF)
 * Enterprise-grade protection against:
 * 1. SQL Injection (SQLi)
 * 2. Remote Code Execution (RCE) & Malicious File Uploads
 * 3. Server-Side Request Forgery (SSRF)
 * 4. Cross-Site Scripting (XSS - Reflected/Stored/DOM)
 * 5. Cross-Site Request Forgery (CSRF)
 * 6. Broken Access Control & IDOR
 * 7. Brute Force & Credential Stuffing
 * 8. Man-In-The-Middle (MitM) & Eavesdropping
 */

// =========================================================================
// 1. MAN-IN-THE-MIDDLE & SECURITY HEADERS (MitM & Eavesdropping)
// =========================================================================
if (!headers_sent()) {
    // Enforce HTTPS HSTS
    if (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains; preload');
    }
    // Prevent Clickjacking
    header('X-Frame-Options: SAMEORIGIN');
    // Prevent MIME-type Sniffing
    header('X-Content-Type-Options: nosniff');
    // XSS Protection for older browsers
    header('X-XSS-Protection: 1; mode=block');
    // Referrer Policy
    header('Referrer-Policy: strict-origin-when-cross-origin');
    // Permissions Policy
    header('Permissions-Policy: geolocation=(self), camera=(self), microphone=()');
    // Session Cookie Settings
    if (PHP_VERSION_ID >= 70300) {
        @ini_set('session.cookie_samesite', 'Strict');
        @ini_set('session.cookie_httponly', '1');
        @ini_set('session.use_only_cookies', '1');
    }
}

// =========================================================================
// 2. CLIENT IP & HELPER RESOLVER
// =========================================================================
if (!function_exists('security_get_client_ip')) {
    function security_get_client_ip(): string {
        $ip = $_SERVER['HTTP_CF_CONNECTING_IP'] 
            ?? $_SERVER['HTTP_X_FORWARDED_FOR'] 
            ?? $_SERVER['HTTP_CLIENT_IP'] 
            ?? $_SERVER['REMOTE_ADDR'] 
            ?? '127.0.0.1';
        if (strpos($ip, ',') !== false) {
            $ip = trim(explode(',', $ip)[0]);
        }
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : '127.0.0.1';
    }
}

// =========================================================================
// 2.5. IP BLACKLIST & BLOCKING ENGINE (Manual & Automatic Banning)
// =========================================================================
if (!function_exists('ensure_blocked_ips_table')) {
    function ensure_blocked_ips_table(): void {
        static $checked = false;
        if ($checked) return;
        $checked = true;
        if (function_exists('dbQuery')) {
            try {
                dbQuery("CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    ip_address VARCHAR(45) NOT NULL UNIQUE,
                    reason VARCHAR(255) DEFAULT 'Suspicious / Unknown Activity',
                    blocked_by VARCHAR(100) DEFAULT 'Admin',
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_ip (ip_address)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
            } catch (Throwable $e) {}
        }
    }
}

if (!function_exists('security_check_ip_blocklist')) {
    function security_check_ip_blocklist(): void {
        $ip = security_get_client_ip();
        if ($ip === '127.0.0.1' || $ip === '::1') return;

        if (function_exists('dbQuery')) {
            try {
                ensure_blocked_ips_table();
                $rows = dbQuery("SELECT * FROM blocked_ips WHERE ip_address = ? LIMIT 1", [$ip]);
                if (!empty($rows)) {
                    $reason = $rows[0]['reason'] ?? 'IP ត្រូវបាន Block ដោយ Admin';
                    http_response_code(403);
                    header('Content-Type: application/json; charset=utf-8');
                    echo json_encode([
                        'success' => false,
                        'error' => 'IP_BLOCKED',
                        'message' => "អាសយដ្ឋាន IP [$ip] របស់អ្នកត្រូវបានរារាំង (Blocked): $reason",
                    ], JSON_UNESCAPED_UNICODE);
                    exit;
                }
            } catch (Throwable $e) {}
        }
    }
}

// Automatically enforce IP Blocklist on every incoming request
security_check_ip_blocklist();

if (!function_exists('security_block_ip')) {
    function security_block_ip(string $ip, string $reason = 'Manual Block', string $blockedBy = 'Admin'): bool {
        $ip = trim($ip);
        if (empty($ip) || $ip === '127.0.0.1' || $ip === '::1') return false;
        if (function_exists('dbQuery')) {
            try {
                ensure_blocked_ips_table();
                dbQuery(
                    "INSERT INTO blocked_ips (ip_address, reason, blocked_by, created_at) VALUES (?, ?, ?, NOW()) ON DUPLICATE KEY UPDATE reason = VALUES(reason), blocked_by = VALUES(blocked_by), created_at = NOW()",
                    [$ip, $reason, $blockedBy]
                );
                return true;
            } catch (Throwable $e) {
                return false;
            }
        }
        return false;
    }
}

if (!function_exists('security_unblock_ip')) {
    function security_unblock_ip(string $ip): bool {
        $ip = trim($ip);
        if (empty($ip)) return false;
        if (function_exists('dbQuery')) {
            try {
                ensure_blocked_ips_table();
                dbQuery("DELETE FROM blocked_ips WHERE ip_address = ?", [$ip]);
                return true;
            } catch (Throwable $e) {
                return false;
            }
        }
        return false;
    }
}

// =========================================================================
// 3. AUDIT LOGGING HOOK (For Security Threat Events)
// =========================================================================
if (!function_exists('security_send_telegram_alert')) {
    /**
     * Send Real-Time Security Incident & Threat Alerts to Telegram Bot
     */
    function security_send_telegram_alert(string $title, string $details, string $severity = 'warning', array $meta = []): bool {
        $botToken = '8658826552:AAFTR4ix-lKua_Zrt_B3ljy1VLVd9M2C1Yo';
        $chatId = null;

        // Try getting chat_id from database settings
        if (function_exists('dbQuery')) {
            try {
                $dr = dbQuery("SELECT chat_id FROM daily_report_telegram_settings WHERE chat_id != '' LIMIT 1");
                if (!empty($dr) && !empty($dr[0]['chat_id'])) {
                    $chatId = trim($dr[0]['chat_id']);
                }
                if (!$chatId) {
                    $st = dbQuery("SELECT setting_value FROM app_settings WHERE setting_key IN ('daily_report_telegram_chat_id', 'security_telegram_chat_id', 'telegram_chat_id') AND setting_value != '' LIMIT 1");
                    if (!empty($st) && !empty($st[0]['setting_value'])) {
                        $chatId = trim($st[0]['setting_value']);
                    }
                }
            } catch (Throwable $e) {}
        }

        if (empty($chatId)) {
            return false;
        }

        $ip = $meta['ip'] ?? security_get_client_ip();
        $ua = $meta['user_agent'] ?? substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 150);
        $timeStr = date('d-M-Y H:i:s');

        $icon = '⚠️';
        if (in_array($severity, ['critical', 'danger'])) {
            $icon = '🚨';
        } elseif ($severity === 'info') {
            $icon = 'ℹ️';
        }

        $text = "<b>{$icon} VVC SECURITY ALERT {$icon}</b>\n";
        $text .= "<b>📌 ព្រឹត្តិការណ៍:</b> " . htmlspecialchars($title) . "\n";
        $text .= "<b>⚡ កម្រិត:</b> " . strtoupper($severity) . "\n";
        $text .= "<b>🌐 អាសយដ្ឋាន IP:</b> <code>" . htmlspecialchars($ip) . "</code>\n";
        $text .= "<b>💻 ឧបករណ៍/Browser:</b> <code>" . htmlspecialchars($ua) . "</code>\n";
        if (!empty($meta['actor'])) {
            $text .= "<b>👤 គណនី/User:</b> " . htmlspecialchars($meta['actor']) . "\n";
        }
        $text .= "<b>📝 ព័ត៌មានលម្អិត:</b> " . htmlspecialchars($details) . "\n";
        $text .= "<b>🕒 ពេលវេលា:</b> {$timeStr}\n";

        $apiUrl = "https://api.telegram.org/bot{$botToken}/sendMessage";
        $payload = [
            'chat_id' => $chatId,
            'text' => $text,
            'parse_mode' => 'HTML',
            'disable_web_page_preview' => true,
        ];

        // Send via cURL
        $ch = curl_init($apiUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($payload),
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_SSL_VERIFYPEER => false,
        ]);
        $res = curl_exec($ch);
        curl_close($ch);

        return !empty($res);
    }
}

if (!function_exists('security_log_threat')) {
    function security_log_threat(string $threatType, string $details, string $severity = 'danger'): void {
        $ip = security_get_client_ip();
        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', 0, 250);
        $uri = substr($_SERVER['REQUEST_URI'] ?? '', 0, 250);

        if (function_exists('log_audit_event')) {
            log_audit_event($threatType, 'security', $uri, $details, $severity, 'Security Guard', 'SYSTEM', 'waf');
        } elseif (function_exists('dbQuery')) {
            try {
                if (function_exists('ensure_audit_logs_table')) {
                    ensure_audit_logs_table();
                }
                dbQuery(
                    "INSERT INTO audit_logs (actor_id, actor_name, actor_role, action, module, target_id, target_name, details, severity, ip_address, user_agent, created_at) VALUES ('SYSTEM', 'Security Guard', 'waf', ?, 'security', ?, ?, ?, ?, ?, ?, NOW())",
                    [$threatType, $uri, $uri, $details, $severity, $ip, $ua]
                );
            } catch (Throwable $e) {}
        }

        // Send instant Telegram alert for dangerous/critical security threats
        if (in_array($severity, ['critical', 'danger', 'warning'])) {
            security_send_telegram_alert($threatType, $details, $severity, [
                'ip' => $ip,
                'user_agent' => $ua,
            ]);
        }
    }
}

// =========================================================================
// 4. SQL INJECTION (SQLi) DEEP SCANNER & WAF FILTER
// =========================================================================
if (!function_exists('security_inspect_sqli')) {
    function security_inspect_sqli($data, $keyPath = ''): void {
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                security_inspect_sqli($v, $keyPath ? "$keyPath.$k" : (string)$k);
            }
            return;
        }

        if (!is_string($data) || strlen($data) < 4) {
            return;
        }

        // High-confidence SQL Injection attack patterns
        $patterns = [
            '/\b(union(\s+all)?\s+select)\b/i',
            '/\b(benchmark\s*\(\s*\d+\s*,\s*.*\))/i',
            '/\b(waitfor\s+delay\s+[\'"]\d+)/i',
            '/\b(sleep\s*\(\s*\d+\s*\))/i',
            '/\b(information_schema\.(tables|columns|schemata))\b/i',
            '/\b(into\s+(outfile|dumpfile))\b/i',
            '/\b(load_file\s*\()/i',
            '/\b(xp_cmdshell|sp_executesql)\b/i',
            '/(--|\#|\/\*).*select\b/i',
            '/\b(select\s+.*\s+from\s+.*\s+where\s+.*--)/i',
            '/\'\s*(or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
            '/"\s*(or|and)\s+[\'"]?\d+[\'"]?\s*=\s*[\'"]?\d+/i',
        ];

        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $data)) {
                $threatDetail = "SQL Injection attempt detected in parameter [$keyPath]: " . substr($data, 0, 150);
                security_log_threat('SQLI_BLOCKED', $threatDetail, 'critical');

                http_response_code(403);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode([
                    'success' => false,
                    'error' => 'SECURITY_VIOLATION',
                    'message' => 'ការស្នើសុំត្រូវបានបដិសេធដោយប្រព័ន្ធសុវត្ថិភាព (SQL Injection Blocked)',
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
        }
    }
}

// Automatically inspect all incoming GET and POST parameters for SQLi
security_inspect_sqli($_GET, 'GET');
security_inspect_sqli($_POST, 'POST');

// =========================================================================
// 5. CROSS-SITE SCRIPTING (XSS) SANITIZATION & WAF
// =========================================================================
if (!function_exists('security_clean_xss')) {
    function security_clean_xss($data) {
        if (is_array($data)) {
            foreach ($data as $k => $v) {
                $data[$k] = security_clean_xss($v);
            }
            return $data;
        }

        if (!is_string($data)) {
            return $data;
        }

        // Dangerous XSS injection markers (quoted and unquoted handlers, scripts, objects)
        $dangerousPatterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/javascript:[^\'"\s]*/i',
            '/vbscript:[^\'"\s]*/i',
            '/\bon\w+\s*=\s*(?:[^\s>]+|[\'"][^\'"]*[\'"])/i', // Catches all onload, onerror, onclick with/without quotes
            '/<iframe\b[^>]*>(.*?)<\/iframe>/is',
            '/<object\b[^>]*>(.*?)<\/object>/is',
            '/<embed\b[^>]*>/i',
            '/<svg\b[^>]*>/is',
        ];

        return preg_replace($dangerousPatterns, '', $data);
    }
}

if (!function_exists('safe_html')) {
    function safe_html(?string $str): string {
        return htmlspecialchars((string)$str, ENT_QUOTES | ENT_HTML5, 'UTF-8');
    }
}

// Clean incoming global superglobals
$_GET = security_clean_xss($_GET);
$_POST = security_clean_xss($_POST);
$_REQUEST = security_clean_xss($_REQUEST);

// =========================================================================
// 6. BRUTE FORCE & CREDENTIAL STUFFING RATE LIMITER
// =========================================================================
if (!function_exists('ensure_security_rate_limits_table')) {
    function ensure_security_rate_limits_table(): void {
        static $ensured = false;
        if ($ensured) return;
        $ensured = true;
        if (function_exists('dbQuery')) {
            dbQuery("CREATE TABLE IF NOT EXISTS security_rate_limits (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                ip_address VARCHAR(50) NOT NULL,
                action_key VARCHAR(100) NOT NULL,
                attempt_count INT DEFAULT 1,
                last_attempt_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                locked_until DATETIME NULL,
                INDEX idx_ip_action (ip_address, action_key),
                INDEX idx_locked (locked_until)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4");
        }
    }
}

if (!function_exists('security_check_login_throttle')) {
    /**
     * Check if client IP or username is locked out due to repeated failed logins.
     * Max 5 failed attempts locks the IP/user for 15 minutes.
     */
    function security_check_login_throttle(string $username): bool {
        if (!function_exists('dbQuery')) return true;
        ensure_security_rate_limits_table();

        $ip = security_get_client_ip();
        $key = 'login_' . md5($ip . '_' . strtolower(trim($username)));

        $rows = dbQuery("SELECT attempt_count, locked_until FROM security_rate_limits WHERE ip_address = ? AND action_key = ? LIMIT 1", [$ip, $key]);
        if (!empty($rows)) {
            $row = $rows[0];
            if (!empty($row['locked_until']) && strtotime($row['locked_until']) > time()) {
                $minsLeft = ceil((strtotime($row['locked_until']) - time()) / 60);
                http_response_code(429);
                header('Content-Type: application/json; charset=utf-8');
                echo json_encode([
                    'success' => false,
                    'error' => 'ACCOUNT_LOCKED',
                    'message' => "គណនី ឬ IP របស់អ្នកត្រូវបានចាក់សោរបណ្តោះអាសន្នដោយសារ Login ខុសលើសពី ៥ ដង។ សូមរង់ចាំ $minsLeft នាទីទៀត!",
                ], JSON_UNESCAPED_UNICODE);
                exit;
            }
        }
        return true;
    }
}

if (!function_exists('security_record_login_result')) {
    function security_record_login_result(string $username, bool $success): void {
        if (!function_exists('dbQuery')) return;
        ensure_security_rate_limits_table();

        $ip = security_get_client_ip();
        $key = 'login_' . md5($ip . '_' . strtolower(trim($username)));

        if ($success) {
            // Reset attempts on successful login
            dbQuery("DELETE FROM security_rate_limits WHERE ip_address = ? AND action_key = ?", [$ip, $key]);
        } else {
            // Increment failed attempts
            $rows = dbQuery("SELECT attempt_count FROM security_rate_limits WHERE ip_address = ? AND action_key = ? LIMIT 1", [$ip, $key]);
            if (!empty($rows)) {
                $newCount = (int)$rows[0]['attempt_count'] + 1;
                $lockedUntil = null;
                if ($newCount >= 5) {
                    // Lockout for 15 minutes (900 seconds)
                    $lockedUntil = date('Y-m-d H:i:s', time() + 900);
                    security_log_threat('BRUTE_FORCE_LOCKOUT', "IP $ip locked out for 15m after 5 failed attempts on user '$username'", 'warning');
                }
                dbQuery("UPDATE security_rate_limits SET attempt_count = ?, last_attempt_at = NOW(), locked_until = ? WHERE ip_address = ? AND action_key = ?", [$newCount, $lockedUntil, $ip, $key]);
            } else {
                dbQuery("INSERT INTO security_rate_limits (ip_address, action_key, attempt_count, last_attempt_at) VALUES (?, ?, 1, NOW())", [$ip, $key]);
            }
        }
    }
}

// =========================================================================
// 7. REMOTE CODE EXECUTION (RCE) & FILE UPLOAD ARMOR
// =========================================================================
if (!function_exists('security_validate_upload')) {
    /**
     * Strictly validate uploaded files to prevent Web Shells and RCE.
     */
    function security_validate_upload(array $file, array $allowedExtensions = ['jpg', 'jpeg', 'png', 'webp', 'pdf', 'mp3', 'wav', 'm4a', 'mp4'], int $maxSizeBytes = 25165824): array {
        if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
            return ['valid' => false, 'error' => 'មិនមានឯកសារ Upload ត្រឹមត្រូវឡើយ។'];
        }

        if ($file['size'] > $maxSizeBytes) {
            return ['valid' => false, 'error' => 'ទំហំឯកសារធំលើសកំណត់ (' . round($maxSizeBytes / 1048576) . ' MB)។'];
        }

        $origName = $file['name'] ?? '';
        $ext = strtolower(pathinfo($origName, PATHINFO_EXTENSION));

        // 1. Blacklist check
        $dangerousExts = ['php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'phps', 'cgi', 'pl', 'py', 'sh', 'bat', 'cmd', 'exe', 'dll', 'jsp', 'asp', 'aspx', 'shtml', 'htaccess', 'env', 'ini', 'config'];
        if (in_array($ext, $dangerousExts) || preg_match('/\.(php|phtml|phar|cgi|pl|py|sh|exe|asp|jsp)(\.|\/|$)/i', $origName)) {
            security_log_threat('RCE_UPLOAD_BLOCKED', "Blocked malicious executable file upload attempt: $origName", 'critical');
            return ['valid' => false, 'error' => 'ប្រភេទឯកសារនេះត្រូវបានហាមឃាត់ដាច់ខាតសម្រាប់សុវត្ថិភាព!'];
        }

        // 2. Whitelist check
        if (!in_array($ext, $allowedExtensions)) {
            return ['valid' => false, 'error' => "ប្រភេទឯកសារ .$ext មិនត្រូវបានអនុញ្ញាតឡើយ។"];
        }

        // 3. Deep Content Inspection for PHP code in images
        $tmpPath = $file['tmp_name'];
        $contentHead = @file_get_contents($tmpPath, false, null, 0, 4096);
        if ($contentHead && preg_match('/(<\?php|<\?=|<script\b|__halt_compiler|eval\s*\(|base64_decode\s*\(|system\s*\(|passthru\s*\()/i', $contentHead)) {
            security_log_threat('RCE_PHP_PAYLOAD_BLOCKED', "Blocked PHP code embedded in image upload: $origName", 'critical');
            return ['valid' => false, 'error' => 'ឯកសារមានផ្ទុកកូដគ្រោះថ្នាក់ (Embedded Script Detected)!'];
        }

        // 4. Safe Hashed Filename Generation
        $safeName = bin2hex(random_bytes(16)) . '_' . time() . '.' . $ext;

        return [
            'valid' => true,
            'safe_filename' => $safeName,
            'extension' => $ext,
        ];
    }
}

// =========================================================================
// 8. SERVER-SIDE REQUEST FORGERY (SSRF) GUARD
// =========================================================================
if (!function_exists('security_is_safe_url')) {
    /**
     * Validate destination URL to prevent SSRF against Localhost, Internal networks, and Cloud Metadata APIs.
     */
    function security_is_safe_url(string $url): bool {
        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['host']) || empty($parsed['scheme'])) {
            return false;
        }

        $scheme = strtolower($parsed['scheme']);
        if (!in_array($scheme, ['http', 'https'])) {
            return false;
        }

        $host = strtolower($parsed['host']);
        // Block Localhost and Cloud Metadata Hostnames
        if (in_array($host, ['localhost', '127.0.0.1', '::1', 'metadata.google.internal', '169.254.169.254'])) {
            return false;
        }

        // Resolve Host IP
        $ip = gethostbyname($host);
        if ($ip === $host && !filter_var($ip, FILTER_VALIDATE_IP)) {
            return false;
        }

        // Check if IP falls into Private / Reserved Ranges (RFC 1918 / Loopback)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
            return false;
        }

        return true;
    }
}

if (!function_exists('security_safe_curl')) {
    /**
     * Safe cURL wrapper with built-in SSRF protection.
     */
    function security_safe_curl(string $url, array $curlOptions = []): array {
        if (!security_is_safe_url($url)) {
            security_log_threat('SSRF_BLOCKED', "Blocked outbound SSRF request to destination: $url", 'critical');
            return ['success' => false, 'error' => 'SSRF Protection: Outbound request to private/internal network is prohibited.'];
        }

        $ch = curl_init($url);
        $defaults = [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 15,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false, // Prevent redirect-based SSRF bypass
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ];

        foreach ($curlOptions as $k => $v) {
            $defaults[$k] = $v;
        }
        curl_setopt_array($ch, $defaults);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($response === false) {
            return ['success' => false, 'error' => $curlError, 'http_code' => $httpCode];
        }

        return ['success' => true, 'response' => $response, 'http_code' => $httpCode];
    }
}

// =========================================================================
// 9. CROSS-SITE REQUEST FORGERY (CSRF) TOKEN SYSTEM
// =========================================================================
if (!function_exists('security_get_csrf_token')) {
    function security_get_csrf_token(): string {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }
        if (empty($_SESSION['csrf_token'])) {
            $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
        }
        return $_SESSION['csrf_token'];
    }
}

if (!function_exists('security_validate_csrf')) {
    function security_validate_csrf(): bool {
        $method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        if (in_array($method, ['GET', 'HEAD', 'OPTIONS'])) {
            return true;
        }

        $token = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? $_POST['csrf_token'] ?? $_GET['csrf_token'] ?? '';
        $bearer = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

        // Allow API tokens / Bearer authentication for Mobile App and REST clients
        if (!empty($bearer) && stripos($bearer, 'Bearer ') === 0) {
            return true;
        }

        if (session_status() !== PHP_SESSION_ACTIVE) {
            @session_start();
        }

        $sessionToken = $_SESSION['csrf_token'] ?? '';
        if (!empty($sessionToken) && hash_equals($sessionToken, (string)$token)) {
            return true;
        }

        return false;
    }
}

// =========================================================================
// 10. BROKEN ACCESS CONTROL & IDOR VALIDATOR
// =========================================================================
if (!function_exists('security_check_ownership')) {
    /**
     * Enforce strict Role-Based Access Control and prevent IDOR parameter tampering.
     */
    function security_check_ownership(?string $requestorRole, ?string $requestorId, ?string $targetId): bool {
        $role = strtolower(trim((string)$requestorRole));
        // Superadmin and Admin have global access
        if (in_array($role, ['superadmin', 'admin', 'hr', 'general_manager', 'director'])) {
            return true;
        }

        // Regular users/employees can only access their own records
        if (!empty($requestorId) && !empty($targetId) && (string)$requestorId === (string)$targetId) {
            return true;
        }

        security_log_threat('IDOR_BLOCKED', "User [$requestorId] ($role) attempted unauthorized access to target resource ID [$targetId]", 'warning');
        return false;
    }
}

// =========================================================================
// 11. LINK & URL ATTACK DEFENSE (Open Redirect, Traversal, Phishing, Dangerous Schemes)
// =========================================================================
if (!function_exists('security_inspect_url_attacks')) {
    /**
     * Scan incoming URI and Query String for Path Traversal, Null Bytes, and Malicious Link exploits.
     */
    function security_inspect_url_attacks(): void {
        $rawUri = $_SERVER['REQUEST_URI'] ?? '';
        $queryString = $_SERVER['QUERY_STRING'] ?? '';
        $pathInfo = $_SERVER['PATH_INFO'] ?? '';

        $targets = [$rawUri, $queryString, $pathInfo];

        // Dangerous URL patterns
        $dangerousPatterns = [
            '/\.\.[\/\\]/i',                      // Directory Traversal ../ or ..\
            '/%2e%2e(%2f|%5c)/i',                 // URL Encoded Traversal %2e%2e%2f
            '/%252e%252e/i',                      // Double URL Encoded Traversal
            '/\x00|%00/i',                         // Null Byte Injection
            '/(etc\/passwd|etc\/shadow|win\.ini|boot\.ini)/i', // Sensitive System Files
            '/\b(javascript|vbscript|data):/i',   // Dangerous URL schemes in URI
            '/(<|>|\"|\'|%3C|%3E|%22)/i',         // Raw HTML / Quotes in Query String
            '/\b(cmd\.exe|powershell|bin\/sh|bin\/bash)\b/i', // Command execution in URI
        ];

        foreach ($targets as $target) {
            if (empty($target)) continue;
            foreach ($dangerousPatterns as $pattern) {
                if (preg_match($pattern, $target)) {
                    $threatDetail = "Malicious Link/URL pattern detected: " . substr($target, 0, 150);
                    security_log_threat('URL_ATTACK_BLOCKED', $threatDetail, 'critical');

                    http_response_code(403);
                    header('Content-Type: application/json; charset=utf-8');
                    echo json_encode([
                        'success' => false,
                        'error' => 'MALICIOUS_LINK_BLOCKED',
                        'message' => 'ការវាយប្រហារតាម Link/URL ត្រូវបានរារាំងដោយប្រព័ន្ធសុវត្ថិភាព (Malicious Link Blocked)',
                    ], JSON_UNESCAPED_UNICODE);
                    exit;
                }
            }
        }
    }
}

// Automatically inspect incoming request URI & query string on every request
security_inspect_url_attacks();

if (!function_exists('security_validate_redirect_url')) {
    /**
     * Prevent Open Redirect vulnerabilities (Phishing via Redirect Links).
     * Only allows safe relative paths or trusted company domains.
     */
    function security_validate_redirect_url(?string $url, string $defaultFallback = '/'): string {
        if (empty($url)) {
            return $defaultFallback;
        }

        $url = trim($url);

        // Disallow dangerous schemes like javascript:, data:, vbscript:
        if (preg_match('/^\s*(javascript|data|vbscript|file):/i', $url)) {
            return $defaultFallback;
        }

        // Relative paths starting with a single '/' (e.g. '/', '/dashboard', '/attendance-reports') are safe
        if ($url === '/' || (strncmp($url, '/', 1) === 0 && strncmp($url, '//', 2) !== 0 && strncmp($url, '/\\', 2) !== 0)) {
            return $url;
        }

        // Parse Absolute URL
        $parsed = parse_url($url);
        if (!$parsed || empty($parsed['host'])) {
            return $defaultFallback;
        }

        $host = strtolower($parsed['host']);
        $allowedDomains = [
            'app.vvc.asia',
            'vvc.asia',
            'kouprey.asia',
            'sksk.asia',
            'localhost',
            '127.0.0.1',
        ];

        foreach ($allowedDomains as $allowed) {
            if ($host === $allowed || str_ends_with($host, '.' . $allowed)) {
                return $url;
            }
        }

        // Untrusted / Phishing domain -> fallback to default
        security_log_threat('OPEN_REDIRECT_BLOCKED', "Blocked suspicious redirect to external domain: $url", 'warning');
        return $defaultFallback;
    }
}

if (!function_exists('safe_url')) {
    /**
     * Sanitize user-provided links (e.g. avatar URLs, external links, social links).
     */
    function safe_url(?string $url): string {
        if (empty($url)) return '';
        $url = trim($url);
        
        // Only allow http, https, mailto, tel
        if (preg_match('/^(https?:\/\/|mailto:|tel:|\/)/i', $url)) {
            return filter_var($url, FILTER_SANITIZE_URL) ?: '';
        }
        
        return '';
    }
}

