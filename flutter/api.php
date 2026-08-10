<?php
/**
 * VVC-HRM API Gateway — flutter/api.php
 * Self-contained entry point that loads all dependencies from the parent directory or current directory.
 * Mobile app calls this URL: https://app.vvc.asia/flutter/api.php
 */

if (ob_get_level() === 0) {
    ob_start();
}

error_reporting(E_ALL);
ini_set('display_errors', 0);

// Resolve the root directory (one level up from flutter/)
$ROOT = dirname(__DIR__);

// ── Quick test/health handler (no DB or requires needed) ──────────────────────
$actionSource = $_POST['action'] ?? $_GET['action'] ?? $_POST['ajax_action'] ?? $_GET['ajax_action'] ?? '';
$action = strtolower(trim($actionSource));

if ($action === 'test' || $action === 'health') {
    while (ob_get_level() > 0) { ob_end_clean(); }
    http_response_code(200);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success'        => true,
        'message'        => 'API is working (flutter)',
        'action_received'=> $action,
        'post_vars'      => $_POST,
        'get_vars'       => $_GET,
        'server_method'  => $_SERVER['REQUEST_METHOD'] ?? 'unknown',
        'root_path'      => $ROOT,
        'root_api_exists'=> file_exists($ROOT . '/api.php'),
    ]);
    exit;
}

// ── Check if main api.php exists in same folder (if deployed directly inside flutter/) ──
if (file_exists(__DIR__ . '/api.php') && __FILE__ !== (__DIR__ . '/api.php')) {
    if (filesize(__DIR__ . '/api.php') > 5000) {
        require_once __DIR__ . '/api.php';
        exit;
    }
}

// ── For all other actions: delegate to root api.php ──────────────────────────
$rootApi = $ROOT . '/api.php';

if (!file_exists($rootApi)) {
    while (ob_get_level() > 0) { ob_end_clean(); }
    http_response_code(500);
    header('Content-Type: application/json; charset=UTF-8');
    echo json_encode([
        'success' => false,
        'message' => 'Root api.php not found at: ' . $rootApi,
    ]);
    exit;
}

// Change to root dir so all __DIR__ references inside api.php resolve correctly
chdir($ROOT);

// Include root api.php — shares same request context ($_GET, $_POST, headers)
require_once $rootApi;


