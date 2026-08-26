<?php
header('Content-Type: text/plain; charset=UTF-8');
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "=== ADMIN_API DIAGNOSTIC ===\n";
$rootAdminApi = __DIR__ . '/../admin_api.php';
echo "root admin_api.php: $rootAdminApi -> " . (file_exists($rootAdminApi) ? "EXISTS (" . filesize($rootAdminApi) . " bytes)" : "MISSING") . "\n";

$_GET['action'] = 'get_meetings';
try {
    require_once $rootAdminApi;
} catch (Throwable $e) {
    echo "ERROR: " . $e->getMessage() . " in " . $e->getFile() . " on line " . $e->getLine() . "\n";
    echo $e->getTraceAsString() . "\n";
}
