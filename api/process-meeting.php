<?php
/**
 * Khmer Meeting Summarizer API (GitHub Models Integration)
 * 
 * This endpoint processes meeting audio files using GitHub Models API:
 * 1. OpenAI Whisper via GitHub Models for Khmer Speech-to-Text
 * 2. OpenAI GPT-4o via GitHub Models for Khmer Meeting Summarization
 * 
 * Endpoint: /api/process-meeting.php
 * Method: POST
 * Content-Type: multipart/form-data
 * 
 * Parameters:
 * - audio_file: Audio file (.m4a, .mp3, .wav)
 * - meeting_id: Meeting ID (optional)
 * - meeting_title: Meeting title (optional)
 * - department: Department name (optional)
 * - api_key: GitHub Personal Access Token (PAT)
 */

header('Content-Type: application/json');
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
$config = [
    'github_pat' => getenv('GITHUB_PAT'),
    'api_auth_key' => getenv('MEETING_API_KEY'),
    'max_file_size' => 25 * 1024 * 1024, // 25MB
    'allowed_formats' => ['m4a', 'mp3', 'wav', 'ogg', 'flac'],
    'github_models_endpoint' => 'https://models.inference.ai.azure.com',
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
if (!isset($_FILES['audio_file']) || $_FILES['audio_file']['error'] !== UPLOAD_ERR_OK) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'No audio file uploaded or upload error']);
    exit;
}

$file = $_FILES['audio_file'];

// Validate file size
if ($file['size'] > $config['max_file_size']) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'File size exceeds maximum limit of 25MB']);
    exit;
}

// Validate file format
$fileExt = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
if (!in_array($fileExt, $config['allowed_formats'])) {
    http_response_code(400);
    echo json_encode(['status' => 'error', 'message' => 'Invalid file format. Allowed: ' . implode(', ', $config['allowed_formats'])]);
    exit;
}

// Get meeting details
$meetingId = $_POST['meeting_id'] ?? null;
$meetingTitle = $_POST['meeting_title'] ?? 'Untitled Meeting';
$department = $_POST['department'] ?? 'General';

try {
    // Step 1: Transcribe audio using OpenAI Whisper via GitHub Models
    $transcript = transcribeWithWhisperGitHub($file['tmp_name'], $config);
    
    if (!$transcript || empty($transcript)) {
        throw new Exception('Failed to transcribe audio');
    }
    
    // Step 2: Generate summary using GPT-4o via GitHub Models
    $summary = generateMeetingSummaryGitHub($transcript, $meetingTitle, $department, $config);
    
    if (!$summary || empty($summary)) {
        throw new Exception('Failed to generate summary');
    }
    
    // Return success response
    echo json_encode([
        'status' => 'success',
        'transcript' => $transcript,
        'summary' => $summary,
        'meeting_title' => $meetingTitle,
        'date' => date('d/m/Y'),
        'department' => $department,
        'meeting_id' => $meetingId
    ]);
    
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode([
        'status' => 'error',
        'message' => $e->getMessage()
    ]);
}

/**
 * Transcribe audio using OpenAI Whisper via GitHub Models API
 */
function transcribeWithWhisperGitHub($filePath, $config) {
    $pat = $config['github_pat'];
    $endpoint = $config['github_models_endpoint'];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $endpoint . '/openai/audio/transcriptions');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $pat,
        'Content-Type: multipart/form-data'
    ]);
    
    $cfile = new CURLFile($filePath, 'audio/' . pathinfo($filePath, PATHINFO_EXTENSION), 'audio.' . pathinfo($filePath, PATHINFO_EXTENSION));
    
    $data = [
        'file' => $cfile,
        'model' => 'whisper-1',
        'language' => 'km', // Khmer
        'response_format' => 'text'
    ];
    
    curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $error = curl_error($ch);
    curl_close($ch);
    
    if ($error) {
        throw new Exception('cURL Error: ' . $error);
    }
    
    if ($httpCode !== 200) {
        throw new Exception('GitHub Models API Error: HTTP ' . $httpCode . ' - ' . $response);
    }
    
    return trim($response);
}

/**
 * Generate meeting summary using GPT-4o via GitHub Models API
 */
function generateMeetingSummaryGitHub($transcript, $meetingTitle, $department, $config) {
    $pat = $config['github_pat'];
    $endpoint = $config['github_models_endpoint'];
    
    $prompt = "សូមសង្ខេបខ្លឹមសារនៃកិច្ចប្រជុំខាងក្រោមនេះជាភាសាខ្មែរឱ្យបានច្បាស់លាស់ ខ្លីខ្លឹម និងមានរបៀបរៀបរយ៖\n\n" .
               "កិច្ចប្រជុំ៖ $meetingTitle\n" .
               "ផ្នែក៖ $department\n\n" .
               "ខ្លឹមសារកិច្ចប្រជុំ៖\n$transcript\n\n" .
               "សូមរាយការណ៍សេចក្តីសង្ខេបតាមរបៀបដូចខាងក្រោម៖\n" .
               "- 💡 ចំណុចសំខាន់ៗនៃកិច្ចប្រជុំ (Key Highlights)\n" .
               "- 🎯 កិច្ចការដែលត្រូវធ្វើបន្ត (Action Items)\n" .
               "- 👤 អ្នកទទួលខុសត្រូវ (Assignees/Roles, if mentioned)";
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $endpoint . '/openai/chat/completions');
    curl_setopt($ch, CURLOPT_POST, 1);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Authorization: Bearer ' . $pat,
        'Content-Type: application/json'
    ]);
    
    $payload = [
        'model' => 'gpt-4o',
        'messages' => [
            ['role' => 'system', 'content' => 'You are a helpful assistant that summarizes meeting transcripts in Khmer language.'],
            ['role' => 'user', 'content' => $prompt]
        ],
        'temperature' => 0.7,
        'max_tokens' => 2000
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
        throw new Exception('GitHub Models API Error: HTTP ' . $httpCode . ' - ' . $response);
    }
    
    $result = json_decode($response, true);
    
    if (isset($result['choices'][0]['message']['content'])) {
        return trim($result['choices'][0]['message']['content']);
    }
    
    throw new Exception('Failed to parse GPT response');
}

