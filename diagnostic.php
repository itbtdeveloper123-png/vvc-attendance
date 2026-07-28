<?php
// Diagnostic script to identify the exact cause of the 500 error
error_reporting(E_ALL);
ini_set('display_errors', 1);

header('Content-Type: text/plain; charset=UTF-8');

echo "=== API Diagnostic Script ===\n\n";

// Test 1: Basic PHP functionality
echo "1. Basic PHP Test: ";
echo "PHP is working (Version: " . phpversion() . ")\n";

// Test 2: File permissions
echo "2. File Permissions:\n";
echo "   api.php readable: " . (is_readable(__DIR__ . '/api.php') ? 'YES' : 'NO') . "\n";
echo "   config.php readable: " . (is_readable(__DIR__ . '/config.php') ? 'YES' : 'NO') . "\n";

// Test 3: Config loading
echo "3. Config Loading: ";
try {
    require_once __DIR__ . '/config.php';
    echo "SUCCESS\n";
} catch (Exception $e) {
    echo "FAILED: " . $e->getMessage() . "\n";
}

// Test 4: Database connection
echo "4. Database Connection: ";
try {
    $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($mysqli->connect_error) {
        echo "FAILED: " . $mysqli->connect_error . "\n";
    } else {
        echo "SUCCESS\n";
        $mysqli->close();
    }
} catch (Exception $e) {
    echo "FAILED: " . $e->getMessage() . "\n";
}

// Test 5: Required extensions
echo "5. PHP Extensions:\n";
$required_extensions = ['mysqli', 'json', 'mbstring'];
foreach ($required_extensions as $ext) {
    echo "   $ext: " . (extension_loaded($ext) ? 'LOADED' : 'NOT LOADED') . "\n";
}

// Test 6: Helper files
echo "6. Helper Files:\n";
$helper_files = [
    'webpush_functions.php',
    'notification_functions.php', 
    'enterprise_helpers.php',
    'ai_tools.php',
    'ai_provider_openai.php',
    'ai_chat_service.php',
    'ai_image_service.php',
];
foreach ($helper_files as $file) {
    echo "   $file: " . (file_exists(__DIR__ . '/' . $file) ? 'EXISTS' : 'MISSING') . "\n";
}

// Test 7: Memory and execution limits
echo "7. PHP Limits:\n";
echo "   Memory Limit: " . ini_get('memory_limit') . "\n";
echo "   Max Execution Time: " . ini_get('max_execution_time') . "s\n";
echo "   Post Max Size: " . ini_get('post_max_size') . "\n";
echo "   Upload Max Filesize: " . ini_get('upload_max_filesize') . "\n";

// Test 8: Error logging
echo "8. Error Logging:\n";
echo "   Error Log: " . ini_get('error_log') . "\n";
echo "   Display Errors: " . (ini_get('display_errors') ? 'ON' : 'OFF') . "\n";
echo "   Error Reporting: " . error_reporting() . "\n";

// Test 9: Include path
echo "9. Include Path:\n";
echo "   " . get_include_path() . "\n";

// Test 10: Try to include api.php with debug
echo "10. API.php Include Test:\n";
try {
    // Simulate a test request
    $_GET['action'] = 'test';
    ob_start();
    include __DIR__ . '/api.php';
    $output = ob_get_clean();
    echo "   API Output: " . substr($output, 0, 200) . "\n";
} catch (Exception $e) {
    echo "   FAILED: " . $e->getMessage() . "\n";
    echo "   File: " . $e->getFile() . "\n";
    echo "   Line: " . $e->getLine() . "\n";
}

echo "\n=== Diagnostic Complete ===\n";
?>