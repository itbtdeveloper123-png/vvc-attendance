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
// 3. AUDIT LOGGING HOOK (For Security Threat Events)
// =========================================================================
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

        // Dangerous XSS injection markers
        $dangerousPatterns = [
            '/<script\b[^>]*>(.*?)<\/script>/is',
            '/javascript:[^\'"\s]*/i',
            '/vbscript:[^\'"\s]*/i',
            '/onload\s*=\s*[\'"][^\'"]*[\'"]/i',
            '/onerror\s*=\s*[\'"][^\'"]*[\'"]/i',
            '/onclick\s*=\s*[\'"][^\'"]*[\'"]/i',
            '/onmouseover\s*=\s*[\'"][^\'"]*[\'"]/i',
            '/<iframe\b[^>]*>(.*?)<\/iframe>/is',
            '/<object\b[^>]*>(.*?)<\/object>/is',
            '/<embed\b[^>]*>/i',
            '/<svg\b[^>]*\bonload\b[^>]*>/is',
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
