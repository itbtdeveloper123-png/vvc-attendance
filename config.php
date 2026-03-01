<?php
// config.php - Central configuration for Database and Telegram

// ===============================================
//          DATABASE CONFIGURATION (Auto-Detect)
// ===============================================
$is_localhost = (
    in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1']) ||
    in_array($_SERVER['SERVER_NAME'] ?? '', ['localhost', '127.0.0.1', '::1']) ||
    (stripos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false) ||
    (PHP_OS_FAMILY === 'Windows')
);

if ($is_localhost) {
    // --- LOCALHOST SETTINGS ---
    define('DB_SERVER', 'localhost');
    define('DB_USERNAME', 'root');           // សម្រាប់ localhost ជាទូទៅប្រើ root
    define('DB_PASSWORD', '');               // សម្រាប់ localhost ជាទូទៅគ្មាន password
    define('DB_NAME', 'samann1_attendance_db');
} else {
    // --- HOSTING SETTINGS ---
    define('DB_SERVER', 'localhost');
    define('DB_USERNAME', 'samann1_attendance_db');
    define('DB_PASSWORD', 'attendance@2025');
    define('DB_NAME', 'samann1_attendance_db');
}

// ===============================================
//          TELEGRAM CONFIGURATION
// ===============================================
define('TELEGRAM_BOT_TOKEN', '7680086124:AAHrvdz-mOx3pO1Ijqvh7BHTeGh2JB5JuwQ');
define('TELEGRAM_CHAT_ID', '-1002802610249');

// ===============================================
//          OTHER SETTINGS
// ===============================================
define('DEFAULT_ADMIN_ID', 'ADMIN001');
define('DEFAULT_ADMIN_PASSWORD', 'adminpass');
define('EARTH_RADIUS_KM', 6371);
define('TOLERANCE', 100);

// ===============================================
//          PUSH NOTIFICATION VAPID KEYS
// ===============================================
define('VAPID_PUBLIC_KEY', 'BAJszQgKFITmC5HEAYR6MJklEVFKPk2_2OnHp519hWeK_eTkdJxTIjFZrTl7l3nsvTOT4XU4vH7gUriK2cNq_WI');
define('VAPID_PRIVATE_KEY', 'OyDzq6uQDpbOK8Nw-dPc07xeEwuItdCmkIOIDizV8-A');

// Set timezone
date_default_timezone_set('Asia/Phnom_Penh');
?>
