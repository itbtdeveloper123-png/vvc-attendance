<?php
require_once __DIR__ . '/db.php';

$appSettings = [];
try {
    $rows = $mysqli->query("SELECT admin_id, setting_key, setting_value FROM app_settings ORDER BY (setting_value != '') ASC, (admin_id = 'SYSTEM_WIDE') ASC");
    if ($rows) {
        while ($r = $rows->fetch_assoc()) {
            if (!empty($r['setting_value']) || !isset($appSettings[$r['setting_key']])) {
                $appSettings[$r['setting_key']] = $r['setting_value'];
            }
        }
    }
} catch (Throwable $e) {}

try {
    $scanRows = $mysqli->query("SELECT admin_id, setting_key, setting_value FROM app_scan_settings ORDER BY (setting_value != '') ASC, (admin_id = 'SYSTEM_WIDE') ASC");
    if ($scanRows) {
        while ($sr = $scanRows->fetch_assoc()) {
            if (!empty($sr['setting_value']) || !isset($appSettings[$sr['setting_key']])) {
                $appSettings[$sr['setting_key']] = $sr['setting_value'];
            }
        }
    }
} catch (Throwable $e) {}

echo json_encode([
    'telegram_bot_token' => $appSettings['telegram_bot_token'] ?? null,
    'telegram_chat_id' => $appSettings['telegram_chat_id'] ?? null,
    'daily_report_telegram_bot_token' => $appSettings['daily_report_telegram_bot_token'] ?? null,
    'daily_report_telegram_chat_id' => $appSettings['daily_report_telegram_chat_id'] ?? null,
    'daily_report_telegram_reporter_id' => $appSettings['daily_report_telegram_reporter_id'] ?? null,
    'attendance_reminder_enabled' => $appSettings['attendance_reminder_enabled'] ?? null,
    'daily_report_telegram_destinations' => $appSettings['daily_report_telegram_destinations'] ?? null,
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE);
