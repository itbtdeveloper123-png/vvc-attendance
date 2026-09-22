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
    echo json_encode([
        'status' => 'online',
        'service' => 'PDF to Word Microservice (Layout & Images Engine)',
        'python_executable' => $pythonBin,
        'converter_script_available' => $scriptExists,
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

$pythonBin = find_python_executable($rootDir);

// 6. Execute Python Converter
$command = escapeshellcmd($pythonBin) . ' '
    . escapeshellarg($scriptPath) . ' '
    . escapeshellarg($pdfFilePath) . ' '
    . escapeshellarg($docxFilePath) . ' '
    . escapeshellarg($khmerFont) . ' 2>&1';

$outputLines = [];
$returnCode = 0;
exec($command, $outputLines, $returnCode);
$fullOutput = implode("\n", $outputLines);

// Clean up input PDF to save disk space
@unlink($pdfFilePath);

// 7. Parse Result JSON
$parsedResult = null;
foreach ($outputLines as $line) {
    if (strpos($line, '__RESULT_JSON__:') === 0) {
        $jsonStr = substr($line, strlen('__RESULT_JSON__:'));
        $parsedResult = json_decode($jsonStr, true);
        break;
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
    'elapsed_seconds' => $parsedResult['elapsed_seconds'] ?? 0.0,
    'font_applied' => $parsedResult['font_applied'] ?? $khmerFont,
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
