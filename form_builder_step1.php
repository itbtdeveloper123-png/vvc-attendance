<?php
// Form Builder Step 1 - Test mb_http functions
error_log("Form Builder Step 1: Starting to load");

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');

error_log("Form Builder Step 1: Charset set");

// Only use mb_http functions if available
if (function_exists('mb_http_output')) {
    mb_http_output('UTF-8');
    error_log("Form Builder Step 1: mb_http_output called");
}
if (function_exists('mb_http_input')) {
    mb_http_input('UTF-8');
    error_log("Form Builder Step 1: mb_http_input called");
}

error_log("Form Builder Step 1: MB functions checked");

session_start();
error_log("Form Builder Step 1: Session started");

require_once __DIR__ . '/config.php';
error_log("Form Builder Step 1: Config loaded");

echo "Form Builder Step 1 - Loaded Successfully<br>";
echo "Session ID: " . session_id() . "<br>";
echo "Admin ID: " . ($_SESSION['admin_id'] ?? 'Not set') . "<br>";
echo "Time: " . date('Y-m-d H:i:s') . "<br>";
echo "Charset: UTF-8<br>";
echo "MB String: " . (extension_loaded('mbstring') ? 'Enabled' : 'Disabled') . "<br>";

error_log("Form Builder Step 1: Page rendered successfully");
?>