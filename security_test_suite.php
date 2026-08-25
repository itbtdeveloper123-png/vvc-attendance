<?php
/**
 * VVC Attendance & HRM - Security Guard Defensive Verification Suite
 * Script សម្រាប់ត្រួតពិនិត្យ និងផ្ទៀងផ្ទាត់ប្រសិទ្ធភាពនៃមុខងារការពារ (Unit Tests)
 * ក្នុង security_guard.php ដោយមិនចាំបាច់ប្រើប្រាស់ Tool ពីខាងក្រៅឡើយ។
 */

// Define CLI environment simulation if needed
if (php_sapi_name() === 'cli') {
    $_SERVER['REMOTE_ADDR'] = '127.0.0.1';
    $_SERVER['REQUEST_URI'] = '/security_test_suite.php';
    $_SERVER['REQUEST_METHOD'] = 'GET';
}

require_once __DIR__ . '/security_guard.php';

header('Content-Type: text/html; charset=utf-8');

$results = [];
$totalTests = 0;
$passedTests = 0;

function run_test(string $category, string $testName, bool $condition, string $details = '') {
    global $results, $totalTests, $passedTests;
    $totalTests++;
    if ($condition) {
        $passedTests++;
    }
    $results[] = [
        'category' => $category,
        'name' => $testName,
        'passed' => $condition,
        'details' => $details,
    ];
}

echo "=== VVC SECURITY DEFENSE TEST SUITE ===\n\n";

// ==========================================
// 1. SSRF DEFENSE TESTS
// ==========================================
$localSafe = security_is_safe_url('http://127.0.0.1/admin');
$cloudMetaSafe = security_is_safe_url('http://169.254.169.254/latest/meta-data/');
$privateIpSafe = security_is_safe_url('http://192.168.1.1/router');
$publicHttpsSafe = security_is_safe_url('https://api.telegram.org');

run_test('SSRF Protection', 'Block Localhost (127.0.0.1)', $localSafe === false, 'ទប់ស្កាត់ការតភ្ជាប់ទៅ Localhost');
run_test('SSRF Protection', 'Block Cloud Metadata (169.254.169.254)', $cloudMetaSafe === false, 'ទប់ស្កាត់ការទាញយក Cloud Metadata');
run_test('SSRF Protection', 'Block Private Network (192.168.x.x)', $privateIpSafe === false, 'ទប់ស្កាត់ការចូលទៅកាន់ Private IP Range');
run_test('SSRF Protection', 'Allow Public HTTPS', $publicHttpsSafe === true, 'អនុញ្ញាតការតភ្ជាប់ទៅកាន់ Domain សាធារណៈសុវត្ថិភាព');

// ==========================================
// 2. XSS SANITIZATION TESTS
// ==========================================
$dirtyXSS = "Hello <script>alert('XSS')</script><img src=x onerror=alert(1)>";
$cleanXSS = security_clean_xss($dirtyXSS);
$hasScriptTag = stripos($cleanXSS, '<script>') !== false;
$hasOnError = stripos($cleanXSS, 'onerror=') !== false;

run_test('XSS Sanitizer', 'Strip <script> tags', !$hasScriptTag, 'លុប Script Tags គ្រោះថ្នាក់ចេញពី Input');
run_test('XSS Sanitizer', 'Strip onerror event handlers', !$hasOnError, 'លុប OnError Event Handlers');

$rawHtml = '<div class="test">Test & "Quotes"</div>';
$safeEncoded = safe_html($rawHtml);
run_test('HTML Output Encoding', 'Encode Special Characters', strpos($safeEncoded, '&lt;div') !== false && strpos($safeEncoded, '&quot;') !== false, 'បម្លែង HTML Entities ត្រឹមត្រូវ');

// ==========================================
// 3. RCE & FILE UPLOAD ARMOR TESTS
// ==========================================
$dangerousPhpFile = [
    'name' => 'shell.php',
    'type' => 'application/x-php',
    'tmp_name' => __FILE__,
    'error' => 0,
    'size' => 1024,
];
$uploadPhpRes = security_validate_upload($dangerousPhpFile);
run_test('File Upload Armor', 'Block .php file upload', $uploadPhpRes['valid'] === false, 'បដិសេធដាច់ខាតឯកសារកូដដែលអាច Execute បាន (.php)');

$dangerousExeFile = [
    'name' => 'malware.exe',
    'type' => 'application/octet-stream',
    'tmp_name' => __FILE__,
    'error' => 0,
    'size' => 2048,
];
$uploadExeRes = security_validate_upload($dangerousExeFile);
run_test('File Upload Armor', 'Block .exe file upload', $uploadExeRes['valid'] === false, 'បដិសេធដាច់ខាតឯកសារ Executable (.exe)');

// ==========================================
// 4. OPEN REDIRECT & URL DEFENSE TESTS
// ==========================================
$maliciousExternalUrl = 'https://evil-phishing-site.com/login';
$validatedUrl = security_validate_redirect_url($maliciousExternalUrl, '/dashboard');
run_test('Open Redirect Defense', 'Block Untrusted External Redirect', $validatedUrl === '/dashboard', 'ប្តូរមកទំព័រដើមសុវត្ថិភាព /dashboard នៅពេលមាន Redirect ទៅក្រៅ');

$safeInternalUrl = '/attendance-reports';
$validatedSafeUrl = security_validate_redirect_url($safeInternalUrl, '/');
run_test('Open Redirect Defense', 'Allow Safe Relative Path', $validatedSafeUrl === '/attendance-reports', 'អនុញ្ញាត Relative Paths ក្នុងប្រព័ន្ធ');

$dangerousScheme = 'javascript:alert(document.cookie)';
$cleanedScheme = safe_url($dangerousScheme);
run_test('Safe URL Sanitizer', 'Block javascript: URI Scheme', empty($cleanedScheme), 'បដិសេធ Scheme គ្រោះថ្នាក់ javascript:');

// ==========================================
// 5. CSRF & ACCESS CONTROL (IDOR) TESTS
// ==========================================
$csrfToken = security_get_csrf_token();
run_test('CSRF Defense', 'Generate Secure 64-char Hex Token', strlen($csrfToken) === 64, 'បង្កើត Token សុវត្ថិភាព 64 តួអក្សរ');

$adminAccess = security_check_ownership('admin', 'ADMIN01', 'EMP999');
$userOwnAccess = security_check_ownership('employee', 'EMP123', 'EMP123');
$userOtherAccess = security_check_ownership('employee', 'EMP123', 'EMP999');

run_test('Access Control (IDOR)', 'Admin Global Resource Access', $adminAccess === true, 'Admin មានសិទ្ធិគ្រប់គ្រងទូទៅ');
run_test('Access Control (IDOR)', 'User Own Record Access', $userOwnAccess === true, 'បុគ្គលិកអាចចូលមើលកំណត់ត្រាផ្ទាល់ខ្លួន');
run_test('Access Control (IDOR)', 'Block User Unauthorized Access (IDOR)', $userOtherAccess === false, 'ទប់ស្កាត់បុគ្គលិកមិនឱ្យចូលមើលទិន្នន័យអ្នកដទៃ');

// ==========================================
// OUTPUT SUMMARY REPORT
// ==========================================
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <title>VVC Security Guard Defense Verification</title>
    <style>
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 24px; }
        .container { max-width: 900px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.5); }
        h1 { color: #38bdf8; display: flex; align-items: center; gap: 10px; font-size: 22px; margin-top: 0; }
        .badge { padding: 4px 10px; border-radius: 20px; font-size: 13px; font-weight: 700; }
        .badge-pass { background: #065f46; color: #34d399; border: 1px solid #059669; }
        .badge-fail { background: #991b1b; color: #f87171; border: 1px solid #dc2626; }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; }
        th, td { padding: 12px 16px; text-align: left; border-bottom: 1px solid #334155; }
        th { background: #0f172a; color: #94a3b8; font-size: 13px; text-transform: uppercase; }
        tr:hover { background: rgba(255,255,255,0.02); }
        .summary-box { background: #0f172a; padding: 16px; border-radius: 12px; margin-bottom: 20px; display: flex; gap: 20px; justify-content: space-around; }
        .stat-item { text-align: center; }
        .stat-num { font-size: 24px; font-weight: 800; color: #38bdf8; }
        .stat-label { font-size: 12px; color: #94a3b8; margin-top: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🛡️ VVC Security Guard — Defensive Verification Suite</h1>
        <p style="color: #94a3b8; font-size: 14px;">របាយការណ៍ធ្វើតេស្តផ្ទៀងផ្ទាត់មុខងារការពារសុវត្ថិភាពប្រព័ន្ធ (Unit & Integration Tests)</p>

        <div class="summary-box">
            <div class="stat-item">
                <div class="stat-num"><?= $totalTests ?></div>
                <div class="stat-label">តេស្តសរុប (Total Tests)</div>
            </div>
            <div class="stat-item">
                <div class="stat-num" style="color: #34d399;"><?= $passedTests ?></div>
                <div class="stat-label">ជោគជ័យ (Passed)</div>
            </div>
            <div class="stat-item">
                <div class="stat-num" style="color: <?= ($totalTests - $passedTests > 0) ? '#f87171' : '#38bdf8' ?>;"><?= $totalTests - $passedTests ?></div>
                <div class="stat-label">បរាជ័យ (Failed)</div>
            </div>
            <div class="stat-item">
                <div class="stat-num" style="color: #34d399;"><?= round(($passedTests / max(1, $totalTests)) * 100) ?>%</div>
                <div class="stat-label">កម្រិតការពារ (Defense Score)</div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th>ផ្នែកការពារ (Category)</th>
                    <th>ឈ្មោះតេស្ត (Test Scenario)</th>
                    <th>លទ្ធផល (Result)</th>
                    <th>ព័ត៌មានលម្អិត (Details)</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($results as $res): ?>
                <tr>
                    <td style="color: #cbd5e1; font-weight: 600;"><?= htmlspecialchars($res['category']) ?></td>
                    <td><?= htmlspecialchars($res['name']) ?></td>
                    <td>
                        <span class="badge <?= $res['passed'] ? 'badge-pass' : 'badge-fail' ?>">
                            <?= $res['passed'] ? '✓ PASS' : '✗ FAIL' ?>
                        </span>
                    </td>
                    <td style="color: #94a3b8; font-size: 13px;"><?= htmlspecialchars($res['details']) ?></td>
                </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
</body>
</html>
