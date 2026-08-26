<?php
/**
 * VVC-HRM Admin API Gateway — flutter/admin_api.php
 * Delegates directly to root admin_api.php so that all updates in git are instantly live.
 */

if (ob_get_level() === 0) {
    ob_start();
}

$ROOT = dirname(__DIR__);
$rootAdminApi = $ROOT . '/admin_api.php';

if (file_exists($rootAdminApi)) {
    require_once $rootAdminApi;
    exit;
}

// Fallback if deployed in same folder
if (file_exists(__DIR__ . '/../admin_api.php')) {
    require_once __DIR__ . '/../admin_api.php';
    exit;
}

while (ob_get_level() > 0) { ob_end_clean(); }
http_response_code(500);
header('Content-Type: application/json; charset=UTF-8');
echo json_encode([
    'success' => false,
    'message' => 'Root admin_api.php not found.'
], JSON_UNESCAPED_UNICODE);
exit;
