<?php
/**
 * API Diagnostic Tool — /flutter/diag.php
 * Access: https://app.vvc.asia/flutter/diag.php
 * DELETE this file after debugging is done!
 */
header('Content-Type: text/plain; charset=UTF-8');
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "=== DIAGNOSTIC REPORT ===\n";
echo "Time: " . date('Y-m-d H:i:s') . "\n";
echo "PHP Version: " . PHP_VERSION . "\n";
echo "Server: " . ($_SERVER['SERVER_SOFTWARE'] ?? 'unknown') . "\n\n";

// 1. Check current directory
echo "--- PATHS ---\n";
echo "__DIR__   = " . __DIR__ . "\n";
echo "cwd       = " . getcwd() . "\n";
$rootApiPath = __DIR__ . '/../api.php';
$rootCfgPath = __DIR__ . '/../config.php';
echo "root api  = " . $rootApiPath . " → " . (file_exists($rootApiPath) ? "EXISTS (".filesize($rootApiPath)." bytes)" : "MISSING!") . "\n";
echo "root cfg  = " . $rootCfgPath . " → " . (file_exists($rootCfgPath) ? "EXISTS" : "MISSING!") . "\n\n";

// 2. Check flutter/api.php itself
echo "--- flutter/api.php ---\n";
$flutterApi = __DIR__ . '/api.php';
echo "Lines: " . count(file($flutterApi)) . "\n";
echo "First 3 lines:\n";
$lines = file($flutterApi);
foreach (array_slice($lines, 0, 5) as $i => $line) {
    echo "  [" . ($i+1) . "] " . rtrim($line) . "\n";
}
echo "\n";

// 3. Try to load config
echo "--- LOADING CONFIG ---\n";
$result = @include_once $rootCfgPath;
if ($result === false) {
    echo "FAILED to include config.php!\n";
} else {
    echo "config.php loaded OK\n";
    echo "DB_SERVER   = " . (defined('DB_SERVER')   ? DB_SERVER   : 'NOT DEFINED') . "\n";
    echo "DB_NAME     = " . (defined('DB_NAME')     ? DB_NAME     : 'NOT DEFINED') . "\n";
    echo "DB_USERNAME = " . (defined('DB_USERNAME') ? DB_USERNAME : 'NOT DEFINED') . "\n";
}
echo "\n";

// 4. Test DB connection
echo "--- DATABASE ---\n";
if (defined('DB_SERVER') && defined('DB_NAME')) {
    $db = @new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($db->connect_error) {
        echo "FAILED: " . $db->connect_error . "\n";
    } else {
        echo "Connected OK\n";
        $db->close();
    }
} else {
    echo "Cannot test — constants not defined\n";
}
echo "\n";

// 5. Check required helper files
echo "--- REQUIRED FILES (from root api.php) ---\n";
$files = [
    'webpush_functions.php',
    'notification_functions.php',
    'enterprise_helpers.php',
    'ai_tools.php',
    'ai_provider_openai.php',
    'ai_chat_service.php',
    'ai_image_service.php',
];
foreach ($files as $f) {
    $path = __DIR__ . '/../' . $f;
    echo ($f . ": " . (file_exists($path) ? "OK" : "MISSING!") . "\n");
}
echo "\n";

// 6. Syntax check on root api.php
echo "--- PHP SYNTAX CHECK ---\n";
if (function_exists('shell_exec')) {
    $phpBin = PHP_BINARY ?: 'php';
    $out = shell_exec($phpBin . ' -l ' . escapeshellarg($rootApiPath) . ' 2>&1');
    echo "php -l api.php: " . trim($out) . "\n";
} else {
    echo "shell_exec() disabled, cannot run syntax check\n";
}
echo "\n";

echo "=== END DIAGNOSTIC ===\n";
