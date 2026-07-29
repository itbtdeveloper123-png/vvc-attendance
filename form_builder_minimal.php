<?php
// Minimal Form Builder - For Testing
error_log("Form Builder Minimal: Starting to load");

session_start();
error_log("Form Builder Minimal: Session started");

require_once __DIR__ . '/config.php';
error_log("Form Builder Minimal: Config loaded");

echo "Form Builder Minimal - Loaded Successfully<br>";
echo "Session ID: " . session_id() . "<br>";
echo "Admin ID: " . ($_SESSION['admin_id'] ?? 'Not set') . "<br>";
echo "Time: " . date('Y-m-d H:i:s') . "<br>";

error_log("Form Builder Minimal: Page rendered successfully");
?>