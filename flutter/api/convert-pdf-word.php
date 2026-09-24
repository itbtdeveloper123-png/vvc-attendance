<?php
/**
 * Gateway delegator for Flutter API
 * Routes /flutter/api/convert-pdf-word.php directly to root /api/convert-pdf-word.php
 */
$ROOT = dirname(__DIR__, 2);
$target = $ROOT . '/api/convert-pdf-word.php';

if (file_exists($target)) {
    require_once $target;
    exit;
}

if (file_exists(__DIR__ . '/../../api/convert-pdf-word.php')) {
    require_once __DIR__ . '/../../api/convert-pdf-word.php';
    exit;
}

http_response_code(500);
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'status' => 'error',
    'message' => 'Backend microservice /api/convert-pdf-word.php not found.'
], JSON_UNESCAPED_UNICODE);
exit;
