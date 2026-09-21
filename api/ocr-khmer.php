<?php
/**
 * Khmer OCR Backend using Google Gemini 1.5 Flash API
 * 
 * This endpoint processes document images and extracts Khmer text
 * using Google Gemini 1.5 Flash's vision capabilities.
 * 
 * Endpoint: /api/ocr-khmer.php
 * Method: POST
 * Content-Type: multipart/form-data
 * 
 * Parameters:
 * - image_file: Document image file (.jpg, .png, .jpeg)
 * - api_key: API authentication key
 */

header('Content-Type: application/json; charset=utf-8');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Load environment variables from .env file
$envFile = __DIR__ . '/../.env';
if (file_exists($envFile)) {
    $lines = file($envFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;
        if (strpos($line, '=') === false) continue;
        list($key, $value) = explode('=', $line, 2);
        putenv(trim($key) . '=' . trim($value));
        $_ENV[trim($key)] = trim($value);
    }
}

// Configuration
if (file_exists(__DIR__ . '/../config.php')) {
    require_once __DIR__ . '/../config.php';
}
if (file_exists(__DIR__ . '/../enterprise_helpers.php')) {
    require_once __DIR__ . '/../enterprise_helpers.php';
}

$dbConn = $mysqli ?? ($conn ?? null);
$allKeys = function_exists('get_all_active_gemini_keys') ? get_all_active_gemini_keys($dbConn) : [];
$activeKey = !empty($allKeys) ? $allKeys[0] : (getenv('GEMINI_API_KEY') ?: '');

$config = [
    'gemini_api_key' => $activeKey,
    'all_gemini_keys' => !empty($allKeys) ? $allKeys : [$activeKey],
    'api_auth_key' => getenv('OCR_API_KEY'),
    'max_file_size' => 10 * 1024 * 1024, // 10MB
    'allowed_formats' => ['jpg', 'jpeg', 'png', 'webp'],
];

// Validate request method
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['status' => 'error', 'message' => 'Method not allowed']);
    exit;
}

// Validate API key
$headers = getallheaders();
$providedKey = $headers['Authorization'] ?? $headers['authorization'] ?? $_POST['api_key'] ?? '';

if ($providedKey !== $config['api_auth_key']) {
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Unauthorized']);
    exit;
}

// Validate file upload
if (!isset($_FILES['image_file']) || $_FILES['image_file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'No image file uploaded or upload error']);
    exit;
}

$file = $_FILES['image_file'];

// Validate file size
if ($file['size'] > $config['max_file_size']) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'File size exceeds maximum limit of 10MB']);
    exit;
}

// Validate file format
$fileExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($fileExt, $config['allowed_formats'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid file format. Allowed: ' . implode(', ', $config['allowed_formats'])]);
    exit;
}

try {
    // Convert image to Base64
    $imageData = file_get_contents($file['tmp_name']);
    $base64Image = base64_encode($imageData);
    $mimeType = mime_content_type($file['tmp_name']);
    
    // Call Gemini 1.5 Flash API
    $extractedText = extractTextWithGemini($base64Image, $mimeType, $config);
    
    if (!$extractedText || empty($extractedText)) {
        throw new Exception('Failed to extract text from image');
    }
    
    // Return success response
    echo json_encode([
        'status' => 'success',
        'extracted_text' => $extractedText,
    ], JSON_UNESCAPED_UNICODE);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => $e->getMessage()
    ]);
}

/**
 * Extract text from image using Google Gemini 1.5 Flash API
 */
function extractTextWithGemini($base64Image, $mimeType, $config) {
    $keys = !empty($config['all_gemini_keys']) ? $config['all_gemini_keys'] : [$config['gemini_api_key']];
    $lastError = '';

    $prompt = "អ្នកជាអ្នកជំនាញផ្នែកស្កេន និងបម្លែងឯកសារខ្មែរ (Khmer Document & OCR Expert)។ សូមធ្វើការអាន និងស្រង់អត្ថបទទាំងអស់ពីឯកសាររូបភាពនេះជាភាសាខ្មែរឱ្យបានសុក្រឹត ១០០% ដោយរក្សាទម្រង់ដើម ចំណងជើង ព័ត៌មានលម្អិត តារាង និងប្រអប់ Checkbox ([x] ឬ [ ]) ឱ្យបានត្រឹមត្រូវបំផុត។ បញ្ចេញតែអត្ថបទសុទ្ធ មិនបាច់ដាក់ពាក្យនាំមុខឡើយ។";

    $payload = [
        'contents' => [
            [
                'parts' => [
                    ['text' => $prompt],
                    [
                        'inline_data' => [
                            'mime_type' => $mimeType,
                            'data' => $base64Image
                        ]
                    ]
                ]
            ]
        ]
    ];
    $jsonPayload = json_encode($payload);

    foreach ($keys as $apiKey) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=' . $apiKey);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $jsonPayload);
        curl_setopt($ch, CURLOPT_TIMEOUT, 45);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            $lastError = 'cURL Error: ' . $error;
            continue;
        }

        if ($httpCode === 200) {
            $result = json_decode($response, true);
            if (isset($result['candidates'][0]['content']['parts'][0]['text'])) {
                return trim($result['candidates'][0]['content']['parts'][0]['text']);
            }
        } else {
            $lastError = 'Gemini API Error: HTTP ' . $httpCode . ' - ' . substr($response, 0, 200);
        }
    }

    throw new Exception('All Gemini keys failed. Last error: ' . $lastError);
}
