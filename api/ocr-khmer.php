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

// Configuration
$config = [
    'gemini_api_key' => getenv('GEMINI_API_KEY'),
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
    $apiKey = $config['gemini_api_key'];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=' . $apiKey);
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
    
    $prompt = "You are an expert Khmer OCR system. Extract ALL text from this document image into accurate, beautifully formatted Khmer text. Preserve numbered lists, line breaks, headings, and paragraph structures. Return ONLY the extracted text with no extra commentary.";
    
    $payload = [
        'contents' => [
            [
                'parts' => [
                    [
                        'text' => $prompt
                    ],
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
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload));
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception('cURL Error: ' . $error);
    }
    
    if ($httpCode !== 200) {
        throw new Exception('Gemini API Error: HTTP ' . $httpCode . ' - ' . $response);
    }
    
    $result = json_decode($response, true);
    
    if (isset($result['candidates'][0]['content']['parts'][0]['text'])) {
        return trim($result['candidates'][0]['content']['parts'][0]['text']);
    }
    
    throw new Exception('Failed to parse Gemini response');
}
