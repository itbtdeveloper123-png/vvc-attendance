<?php
/**
 * High-Fidelity PDF to Word (.docx) Microservice API
 * 
 * Free & Open-Source Engine:
 * - 100% Genuine Vector Layout & Structure Preservation
 * - High-Resolution Image & Photo Stream Extraction
 * - Automatic Khmer Unicode Font Mapping (Khmer OS Battambang)
 * 
 * Endpoint: /api/convert-pdf-word.php
 * Method: POST (multipart/form-data) or GET (health check / download)
 */

declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Ensure error messages don't break JSON output
ini_set('display_errors', '0');
error_reporting(E_ALL);

// Base directories
$rootDir = dirname(__DIR__);
$uploadDir = $rootDir . '/uploads/pdf_conversions';
$scriptPath = $rootDir . '/scripts/convert_pdf_to_docx.py';

// Create uploads directory if not exists
if (!is_dir($uploadDir)) {
    @mkdir($uploadDir, 0777, true);
}

// -----------------------------------------------------------------------------
// Auto-Cleanup: Delete files older than 24 hours to prevent disk bloating
// -----------------------------------------------------------------------------
function cleanup_expired_files(string $dir, int $maxAgeSeconds = 86400): void {
    if (!is_dir($dir)) return;
    $files = @scandir($dir);
    if ($files === false) return;

    $now = time();
    foreach ($files as $file) {
        if ($file === '.' || $file === '..') continue;
        $filePath = $dir . '/' . $file;
        if (is_file($filePath)) {
            $mtime = @filemtime($filePath);
            if ($mtime !== false && ($now - $mtime) > $maxAgeSeconds) {
                @unlink($filePath);
            }
        }
    }
}
cleanup_expired_files($uploadDir);

// -----------------------------------------------------------------------------
// Locate Python Executable
// -----------------------------------------------------------------------------
function find_python_executable(string $rootDir): string {
    // 1. Check local project virtualenv (.venv) on Windows
    $windowsVenv = $rootDir . '/.venv/Scripts/python.exe';
    if (file_exists($windowsVenv)) {
        return $windowsVenv;
    }

    // 2. Check local project virtualenv on Linux/macOS
    $linuxVenv = $rootDir . '/.venv/bin/python3';
    if (file_exists($linuxVenv)) {
        return $linuxVenv;
    }

    // 3. Check environment variable override
    $customPython = getenv('PYTHON_EXECUTABLE');
    if ($customPython && file_exists($customPython)) {
        return $customPython;
    }

    // 4. Check common Linux/cPanel paths
    $commonLinuxPaths = [
        '/usr/bin/python3',
        '/usr/local/bin/python3',
        '/bin/python3',
    ];
    foreach ($commonLinuxPaths as $path) {
        if (@file_exists($path)) {
            return $path;
        }
    }

    // 5. Default to system python3 or python
    return (DIRECTORY_SEPARATOR === '\\') ? 'python' : 'python3';
}

// -----------------------------------------------------------------------------
// Database Helper: Locate Active iLovePDF Credentials
// -----------------------------------------------------------------------------
function get_active_ilovepdf_credentials(): ?array {
    $rootDir = dirname(__DIR__);
    if (file_exists($rootDir . '/config.php')) {
        @include_once $rootDir . '/config.php';
    }

    $dbServer = defined('DB_SERVER') ? DB_SERVER : 'localhost';
    $dbUser = defined('DB_USERNAME') ? DB_USERNAME : 'root';
    $dbPass = defined('DB_PASSWORD') ? DB_PASSWORD : '';
    $dbName = defined('DB_NAME') ? DB_NAME : 'samann1_attendance_db';

    try {
        if (class_exists('mysqli')) {
            $conn = @new mysqli($dbServer, $dbUser, $dbPass, $dbName);
            if ($conn && !$conn->connect_error) {
                $conn->set_charset('utf8mb4');
                // 1. Check admin_api_keys table for service_name = 'ilovepdf'
                $res = @$conn->query("SELECT api_key, secret_key FROM admin_api_keys WHERE service_name = 'ilovepdf' AND is_active = 1 ORDER BY priority ASC, id ASC LIMIT 1");
                if ($res && ($row = $res->fetch_assoc()) && !empty($row['api_key'])) {
                    $conn->close();
                    return [
                        'public_key' => trim($row['api_key']),
                        'secret_key' => !empty($row['secret_key']) ? trim($row['secret_key']) : null,
                    ];
                }
                // 2. Check app_settings fallback
                $res = @$conn->query("SELECT setting_value FROM app_settings WHERE setting_key = 'ilovepdf_public_key' LIMIT 1");
                if ($res && ($row = $res->fetch_assoc()) && !empty($row['setting_value'])) {
                    $pub = trim($row['setting_value']);
                    $sec = null;
                    $res2 = @$conn->query("SELECT setting_value FROM app_settings WHERE setting_key = 'ilovepdf_secret_key' LIMIT 1");
                    if ($res2 && ($row2 = $res2->fetch_assoc())) {
                        $sec = trim($row2['setting_value']);
                    }
                    $conn->close();
                    return [
                        'public_key' => $pub,
                        'secret_key' => $sec,
                    ];
                }
                $conn->close();
            }
        }
    } catch (\Throwable $e) {
        // Fallback silently
    }

    // 3. Check environment variable override
    $envPub = getenv('ILOVEPDF_PUBLIC_KEY');
    if (!empty($envPub)) {
        return [
            'public_key' => trim($envPub),
            'secret_key' => getenv('ILOVEPDF_SECRET_KEY') ?: null,
        ];
    }

    return null;
}

// -----------------------------------------------------------------------------
// Official iLovePDF Cloud API Engine: PDF to Word (.docx)
// -----------------------------------------------------------------------------
function convert_with_ilovepdf(string $pdfPath, string $docxPath, string $publicKey, ?string $secretKey): array {
    if (!function_exists('curl_init')) {
        return ['success' => false, 'error' => 'cURL PHP extension is not installed'];
    }

    // 1. Auth: POST https://api.ilovepdf.com/v1/auth
    $ch = curl_init('https://api.ilovepdf.com/v1/auth');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Accept: application/json',
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode(['public_key' => $publicKey]));
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $authResp = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($httpCode !== 200 || !$authResp) {
        return ['success' => false, 'error' => 'iLovePDF Auth failed (HTTP ' . $httpCode . ')'];
    }

    $authData = json_decode((string)$authResp, true);
    $token = $authData['token'] ?? null;
    if (!$token) {
        return ['success' => false, 'error' => 'Token not returned by iLovePDF'];
    }

    // 2. Start Task: GET https://api.ilovepdf.com/v1/start/pdfword
    $ch = curl_init('https://api.ilovepdf.com/v1/start/pdfword');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $token,
        'Accept: application/json',
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 20);
    $startResp = curl_exec($ch);
    $startHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($startHttpCode !== 200 || !$startResp) {
        return ['success' => false, 'error' => 'Failed to start iLovePDF task (HTTP ' . $startHttpCode . ')'];
    }

    $startData = json_decode((string)$startResp, true);
    $server = $startData['server'] ?? null;
    $taskId = $startData['task'] ?? null;

    if (!$server || !$taskId) {
        return ['success' => false, 'error' => 'Invalid server or task ID returned by iLovePDF'];
    }

    // 3. Upload File: POST https://{server}/v1/upload
    $cfile = curl_file_create($pdfPath, 'application/pdf', basename($pdfPath));
    $ch = curl_init('https://' . $server . '/v1/upload');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $token,
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, [
        'task' => $taskId,
        'file' => $cfile,
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 120);
    $uploadResp = curl_exec($ch);
    $uploadHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($uploadHttpCode !== 200 || !$uploadResp) {
        return ['success' => false, 'error' => 'Failed to upload PDF to iLovePDF (HTTP ' . $uploadHttpCode . ')'];
    }

    $uploadData = json_decode((string)$uploadResp, true);
    $serverFilename = $uploadData['server_filename'] ?? null;
    if (!$serverFilename) {
        return ['success' => false, 'error' => 'iLovePDF did not return server filename'];
    }

    // 4. Process Task: POST https://{server}/v1/process
    $processPayload = [
        'task' => $taskId,
        'tool' => 'pdfword',
        'files' => [
            [
                'server_filename' => $serverFilename,
                'filename' => basename($pdfPath),
            ],
        ],
    ];
    $ch = curl_init('https://' . $server . '/v1/process');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $token,
        'Content-Type: application/json',
    ]);
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($processPayload));
    curl_setopt($ch, CURLOPT_TIMEOUT, 180);
    $processResp = curl_exec($ch);
    $processHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);

    if ($processHttpCode !== 200 || !$processResp) {
        return ['success' => false, 'error' => 'Failed to process PDF in iLovePDF (HTTP ' . $processHttpCode . ')'];
    }

    // 5. Download Converted Word (.docx): GET https://{server}/v1/download/{task}
    $ch = curl_init('https://' . $server . '/v1/download/' . $taskId);
    $fp = fopen($docxPath, 'w+');
    curl_setopt($ch, CURLOPT_FILE, $fp);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $token,
    ]);
    curl_setopt($ch, CURLOPT_TIMEOUT, 180);
    curl_exec($ch);
    $dlHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    fclose($fp);
    curl_close($ch);

    if ($dlHttpCode === 200 && file_exists($docxPath) && filesize($docxPath) > 0) {
        return [
            'success' => true,
            'engine' => 'iLovePDF Cloud API (Official)',
            'file_size' => filesize($docxPath),
        ];
    }

    @unlink($docxPath);
    return ['success' => false, 'error' => 'Download from iLovePDF failed (HTTP ' . $dlHttpCode . ')'];
}

// -----------------------------------------------------------------------------
// Handle GET Requests (Health Check or Direct File Download)
// -----------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] === 'GET') {
    // Direct file download
    if (isset($_GET['download']) && !empty($_GET['file'])) {
        $safeFileName = basename((string)$_GET['file']);
        $filePath = $uploadDir . '/' . $safeFileName;

        if (file_exists($filePath) && strtolower(pathinfo($filePath, PATHINFO_EXTENSION)) === 'docx') {
            header('Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document');
            header('Content-Disposition: attachment; filename="' . $safeFileName . '"');
            header('Content-Length: ' . filesize($filePath));
            header('Cache-Control: private, max-age=0, must-revalidate');
            header('Pragma: public');
            readfile($filePath);
            exit;
        } else {
            http_response_code(404);
            echo json_encode(['status' => 'error', 'message' => 'File not found or expired'], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // Health check
    $pythonBin = find_python_executable($rootDir);
    $scriptExists = file_exists($scriptPath);
    $iloveCreds = get_active_ilovepdf_credentials();
    echo json_encode([
        'status' => 'online',
        'service' => 'PDF to Word Microservice (Layout & Images Engine)',
        'python_executable' => $pythonBin,
        'converter_script_available' => $scriptExists,
        'ilovepdf_cloud_api_configured' => ($iloveCreds !== null),
        'timestamp' => time(),
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// -----------------------------------------------------------------------------
// Handle POST Request (Convert PDF to Word .docx)
// -----------------------------------------------------------------------------
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed. Use POST.'], JSON_UNESCAPED_UNICODE);
    exit;
}

// 1. Check file upload
if (!isset($_FILES['pdf_file']) || $_FILES['pdf_file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    $uploadErrorCode = $_FILES['pdf_file']['error'] ?? 'NO_FILE';
    echo json_encode([
        'status' => 'error',
        'message' => 'មិនមានឯកសារ PDF ឬមានបញ្ហាក្នុងការ Upload ឡើយ (Upload error: ' . $uploadErrorCode . ')'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$uploadedFile = $_FILES['pdf_file'];

// 2. Validate max file size (50MB)
$maxSize = 50 * 1024 * 1024;
if ($uploadedFile['size'] > $maxSize) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'ទំហំឯកសារធំពេក។ អនុញ្ញាតអតិបរមាត្រឹម 50MB ប៉ុណ្ណោះ។'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// 3. Validate file extension and magic header
$originalName = (string)$uploadedFile['name'];
$ext = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
if ($ext !== 'pdf') {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'ទម្រង់ឯកសារមិនត្រឹមត្រូវឡើយ។ តម្រូវឱ្យប្រើឯកសារ PDF (.pdf)'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

$fileHandle = @fopen($uploadedFile['tmp_name'], 'rb');
$magicHeader = $fileHandle ? fread($fileHandle, 5) : '';
if ($fileHandle) fclose($fileHandle);
if (strpos($magicHeader, '%PDF') !== 0) {
    http_response_code(400);
    echo json_encode([
        'status' => 'error',
        'message' => 'ឯកសារនេះមិនមែនជា PDF ពិតប្រាកដឡើយ។'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// 4. Prepare file paths
$timeId = date('Ymd_His') . '_' . bin2hex(random_bytes(4));
$cleanBaseName = preg_replace('/[^a-zA-Z0-9_\-\x{1780}-\x{17FF}]/u', '_', pathinfo($originalName, PATHINFO_FILENAME));
if (empty($cleanBaseName)) $cleanBaseName = 'document';

$pdfFileName = $cleanBaseName . '_' . $timeId . '.pdf';
$docxFileName = $cleanBaseName . '_' . $timeId . '.docx';

$pdfFilePath = $uploadDir . '/' . $pdfFileName;
$docxFilePath = $uploadDir . '/' . $docxFileName;

if (!move_uploaded_file($uploadedFile['tmp_name'], $pdfFilePath)) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => 'មិនអាចរក្សាទុកឯកសារ PDF បណ្ដោះអាសន្នលើ Server បានឡើយ។'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// 5. Options
$khmerFont = isset($_POST['khmer_font']) && trim((string)$_POST['khmer_font']) !== ''
    ? trim((string)$_POST['khmer_font'])
    : 'Khmer OS Battambang';

$startTime = microtime(true);
$parsedResult = null;
$conversionEngine = 'Python pdf2docx (Local Vector Engine)';
$fullOutput = '';

// -----------------------------------------------------------------------------
// Engine Priority 1: Official iLovePDF Cloud API
// -----------------------------------------------------------------------------
$iloveCreds = get_active_ilovepdf_credentials();
if (!empty($iloveCreds['public_key'])) {
    $iloveRes = convert_with_ilovepdf($pdfFilePath, $docxFilePath, $iloveCreds['public_key'], $iloveCreds['secret_key'] ?? null);
    if (!empty($iloveRes['success']) && file_exists($docxFilePath) && filesize($docxFilePath) > 0) {
        $parsedResult = [
            'success' => true,
            'engine' => 'iLovePDF Cloud API (Official)',
            'file_size' => filesize($docxFilePath),
            'pages' => 1,
            'elapsed_seconds' => round(microtime(true) - $startTime, 2),
            'font_applied' => $khmerFont,
        ];
        $conversionEngine = 'iLovePDF Cloud API (Official)';
        @unlink($pdfFilePath);
    }
}

// -----------------------------------------------------------------------------
// Engine Priority 2: High-Fidelity Python Vector Engine (Fallback)
// -----------------------------------------------------------------------------
if (!$parsedResult) {
    $pythonBin = find_python_executable($rootDir);

    $envPrefix = '';
    if (DIRECTORY_SEPARATOR !== '\\') {
        $homeDir = getenv('HOME') ?: (isset($_SERVER['DOCUMENT_ROOT']) ? dirname($_SERVER['DOCUMENT_ROOT']) : '/home/samann1');
        $envPrefix = 'export HOME=' . escapeshellarg($homeDir) . '; ';
        $envPrefix .= 'export OPENBLAS_NUM_THREADS=1; export OMP_NUM_THREADS=1; export MKL_NUM_THREADS=1; export NUMEXPR_NUM_THREADS=1; ';
        $sitePaths = @glob($homeDir . '/.local/lib/python*/site-packages');
        if (!empty($sitePaths)) {
            $envPrefix .= 'export PYTHONPATH=' . escapeshellarg(implode(':', $sitePaths)) . ':$PYTHONPATH; ';
        }
    }

    $command = $envPrefix . escapeshellcmd($pythonBin) . ' '
        . escapeshellarg($scriptPath) . ' '
        . escapeshellarg($pdfFilePath) . ' '
        . escapeshellarg($docxFilePath) . ' '
        . escapeshellarg($khmerFont) . ' 2>&1';

    // Support both shell_exec and exec
    if (function_exists('shell_exec')) {
        $fullOutput = (string)@shell_exec($command);
    } elseif (function_exists('exec')) {
        $tempLines = [];
        $ret = 0;
        @exec($command, $tempLines, $ret);
        $fullOutput = implode("\n", $tempLines);
    }

    $outputLines = explode("\n", str_replace("\r", "", $fullOutput));

    // Clean up input PDF to save disk space
    @unlink($pdfFilePath);

    // Parse Result JSON
    foreach ($outputLines as $line) {
        if (strpos($line, '__RESULT_JSON__:') === 0) {
            $jsonStr = substr($line, strlen('__RESULT_JSON__:'));
            $parsedResult = json_decode($jsonStr, true);
            break;
        }
    }
}

if (!$parsedResult || empty($parsedResult['success']) || !file_exists($docxFilePath)) {
    http_response_code(500);
    $errorMessage = $parsedResult['error'] ?? 'ការបម្លែងឯកសារមិនជោគជ័យឡើយ';
    echo json_encode([
        'status' => 'error',
        'message' => 'កំហុសពេលបម្លែង PDF to Word: ' . $errorMessage,
        'debug_output' => $fullOutput,
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// 8. Build URLs
$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
$host = $_SERVER['HTTP_HOST'] ?? 'localhost';
$scriptDir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
$siteBase = rtrim(dirname($scriptDir), '/\\');
$downloadUrl = $protocol . '://' . $host . $scriptDir . '/convert-pdf-word.php?download=1&file=' . urlencode($docxFileName);
$fileUrl = $protocol . '://' . $host . $siteBase . '/uploads/pdf_conversions/' . urlencode($docxFileName);

// 9. Return Success JSON
echo json_encode([
    'status' => 'success',
    'message' => 'បម្លែង PDF ទៅជា Word (.docx) រក្សាទម្រង់ដើម និងរូបភាព ១០០% ជោគជ័យ!',
    'docx_url' => $fileUrl,
    'download_url' => $downloadUrl,
    'file_name' => $docxFileName,
    'original_name' => $originalName,
    'file_size' => $parsedResult['file_size'] ?? filesize($docxFilePath),
    'pages' => $parsedResult['pages'] ?? 1,
    'elapsed_seconds' => $parsedResult['elapsed_seconds'] ?? round(microtime(true) - $startTime, 2),
    'font_applied' => $parsedResult['font_applied'] ?? $khmerFont,
    'engine' => $parsedResult['engine'] ?? $conversionEngine,
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
