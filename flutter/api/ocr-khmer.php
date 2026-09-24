<?php
/**
 * Gateway delegator for Flutter API
 * Routes /flutter/api/ocr-khmer.php directly to root /api/ocr-khmer.php
 */
$ROOT = dirname(__DIR__, 2);
$target = $ROOT . '/api/ocr-khmer.php';

if (file_exists($target)) {
    require_once $target;
    exit;
}

if (file_exists(__DIR__ . '/../../api/ocr-khmer.php')) {
    require_once __DIR__ . '/../../api/ocr-khmer.php';
    exit;
}

http_response_code(500);
header('Content-Type: application/json; charset=utf-8');
echo json_encode([
    'status' => 'error',
    'message' => 'Backend microservice /api/ocr-khmer.php not found.'
], JSON_UNESCAPED_UNICODE);
exit;
