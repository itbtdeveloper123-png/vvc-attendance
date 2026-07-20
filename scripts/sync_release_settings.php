<?php

declare(strict_types=1);

function releaseSyncOut(string $message): void
{
    fwrite(STDOUT, $message . PHP_EOL);
}

function releaseSyncErr(string $message, int $exitCode = 1): void
{
    fwrite(STDERR, $message . PHP_EOL);
    exit($exitCode);
}

function releaseSyncThrow(string $message): void
{
    throw new RuntimeException($message);
}

function releaseSyncBoolToDb(bool $value): string
{
    return $value ? '1' : '0';
}

function releaseSyncParsePubspec(string $pubspecPath): array
{
    if (!is_file($pubspecPath)) {
        releaseSyncErr("pubspec.yaml not found: {$pubspecPath}");
    }

    $content = (string) file_get_contents($pubspecPath);
    if (!preg_match('/^version:\s*([^\s#]+)\s*$/mi', $content, $matches)) {
        releaseSyncErr("Unable to find a valid version line in {$pubspecPath}");
    }

    $rawVersion = trim($matches[1]);
    $parts = explode('+', $rawVersion, 2);
    $versionName = trim($parts[0]);
    $buildNumber = isset($parts[1]) ? trim($parts[1]) : '1';

    if ($versionName === '' || !preg_match('/^\d+(?:\.\d+)*(?:[-+a-zA-Z0-9._]*)?$/', $versionName)) {
        releaseSyncErr("Invalid version name parsed from pubspec.yaml: {$versionName}");
    }

    if ($buildNumber === '' || !ctype_digit($buildNumber)) {
        releaseSyncErr("Invalid build number parsed from pubspec.yaml: {$buildNumber}");
    }

    return [
        'raw' => $rawVersion,
        'version' => $versionName,
        'build' => $buildNumber,
    ];
}

function releaseSyncReadSetting(mysqli $mysqli, string $key, string $default = ''): string
{
    $stmt = $mysqli->prepare("SELECT setting_value FROM app_scan_settings WHERE admin_id = 'SYSTEM_WIDE' AND setting_key = ? LIMIT 1");
    if (!$stmt) {
        releaseSyncThrow('Failed to prepare read statement: ' . $mysqli->error);
    }

    $stmt->bind_param('s', $key);
    $stmt->execute();
    $result = $stmt->get_result();
    $value = $default;
    if ($result && $row = $result->fetch_assoc()) {
        $value = (string) ($row['setting_value'] ?? $default);
    }
    $stmt->close();

    return $value;
}

function releaseSyncWriteSetting(mysqli $mysqli, string $key, string $value): void
{
    $stmt = $mysqli->prepare(
        "INSERT INTO app_scan_settings (admin_id, setting_key, setting_value)
         VALUES ('SYSTEM_WIDE', ?, ?)
         ON DUPLICATE KEY UPDATE setting_value = VALUES(setting_value)"
    );
    if (!$stmt) {
        releaseSyncThrow('Failed to prepare write statement: ' . $mysqli->error);
    }

    $stmt->bind_param('ss', $key, $value);
    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();
        releaseSyncThrow('Failed to save setting "' . $key . '": ' . $error);
    }
    $stmt->close();
}

function releaseSyncCleanupPerAdminOverrides(mysqli $mysqli, array $keys): void
{
    if ($keys === []) {
        return;
    }

    $placeholders = implode(',', array_fill(0, count($keys), '?'));
    $types = str_repeat('s', count($keys));
    $sql = "DELETE FROM app_scan_settings WHERE admin_id <> 'SYSTEM_WIDE' AND setting_key IN ({$placeholders})";
    $stmt = $mysqli->prepare($sql);
    if (!$stmt) {
        releaseSyncThrow('Failed to prepare cleanup statement: ' . $mysqli->error);
    }

    $stmt->bind_param($types, ...$keys);
    if (!$stmt->execute()) {
        $error = $stmt->error;
        $stmt->close();
        releaseSyncThrow('Failed to clean stale per-admin overrides: ' . $error);
    }
    $stmt->close();
}

$repoRoot = dirname(__DIR__);
$defaults = [
    'pubspec' => $repoRoot . DIRECTORY_SEPARATOR . 'flutter_app' . DIRECTORY_SEPARATOR . 'pubspec.yaml',
    'apk-url' => 'https://app.vvc.asia/flutter/app-arm64-v8a-release.apk',
];

$options = getopt('', [
    'pubspec::',
    'version::',
    'build::',
    'apk-url::',
    'apk-path::',
    'update-message::',
    'db-server::',
    'db-name::',
    'db-user::',
    'db-pass::',
    'force-update',
    'no-force-update',
    'help',
]);

if (isset($options['help'])) {
    releaseSyncOut('Usage: php scripts/sync_release_settings.php [--pubspec=path] [--apk-url=url] [--apk-path=path] [--update-message=text] [--db-server=host --db-name=name --db-user=user --db-pass=pass] [--force-update|--no-force-update]');
    exit(0);
}

$pubspecPath = isset($options['pubspec']) ? (string) $options['pubspec'] : $defaults['pubspec'];
$pubspecInfo = releaseSyncParsePubspec($pubspecPath);

$versionName = isset($options['version']) ? trim((string) $options['version']) : $pubspecInfo['version'];
$buildNumber = isset($options['build']) ? trim((string) $options['build']) : $pubspecInfo['build'];
$apkUrl = isset($options['apk-url']) ? trim((string) $options['apk-url']) : $defaults['apk-url'];
$apkPath = isset($options['apk-path']) ? trim((string) $options['apk-path']) : '';
$updateMessageOption = isset($options['update-message']) ? trim((string) $options['update-message']) : null;

if ($versionName === '') {
    releaseSyncErr('Version name cannot be empty.');
}
if ($buildNumber === '' || !ctype_digit($buildNumber)) {
    releaseSyncErr('Build number must be a whole number.');
}
if ($apkUrl === '') {
    releaseSyncErr('APK URL cannot be empty.');
}

require_once $repoRoot . DIRECTORY_SEPARATOR . 'config.php';

$dbServer = isset($options['db-server']) ? trim((string) $options['db-server']) : DB_SERVER;
$dbName = isset($options['db-name']) ? trim((string) $options['db-name']) : DB_NAME;
$dbUser = isset($options['db-user']) ? trim((string) $options['db-user']) : DB_USERNAME;
$dbPass = isset($options['db-pass']) ? (string) $options['db-pass'] : DB_PASSWORD;

mysqli_report(MYSQLI_REPORT_OFF);
try {
    $mysqli = new mysqli($dbServer, $dbUser, $dbPass, $dbName);
} catch (Throwable $throwable) {
    releaseSyncErr('Database connection failed: ' . $throwable->getMessage());
}
if ($mysqli->connect_error) {
    releaseSyncErr('Database connection failed: ' . $mysqli->connect_error);
}
$mysqli->set_charset('utf8mb4');
$mysqli->query("SET time_zone = '+07:00'");
if (!$mysqli->query("CREATE TABLE IF NOT EXISTS app_scan_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    admin_id VARCHAR(64) NOT NULL DEFAULT 'SYSTEM_WIDE',
    setting_key VARCHAR(100) NOT NULL,
    setting_value LONGTEXT,
    UNIQUE KEY uniq_scan (admin_id, setting_key)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci")) {
    releaseSyncErr('Failed to ensure app_scan_settings table: ' . $mysqli->error);
}

$existingMessage = releaseSyncReadSetting($mysqli, 'app_update_message', '');
$existingForceUpdate = releaseSyncReadSetting($mysqli, 'app_force_update', '0');

$updateMessage = $updateMessageOption;
if ($updateMessage === null || $updateMessage === '') {
    $updateMessage = $existingMessage !== ''
        ? $existingMessage
        : "A new app version V{$versionName} is available. Please update to continue.";
}

$forceUpdate = $existingForceUpdate === '1';
if (isset($options['force-update']) && isset($options['no-force-update'])) {
    releaseSyncErr('Use either --force-update or --no-force-update, not both.');
}
if (isset($options['force-update'])) {
    $forceUpdate = true;
} elseif (isset($options['no-force-update'])) {
    $forceUpdate = false;
}

$settingsToSync = [
    'app_latest_version' => $versionName,
    'app_latest_build' => $buildNumber,
    'app_apk_url' => $apkUrl,
    'app_update_message' => $updateMessage,
    'app_force_update' => releaseSyncBoolToDb($forceUpdate),
];

try {
    if (method_exists($mysqli, 'begin_transaction')) {
        $mysqli->begin_transaction();
    } else {
        $mysqli->autocommit(false);
    }

    foreach ($settingsToSync as $key => $value) {
        releaseSyncWriteSetting($mysqli, $key, $value);
    }
    releaseSyncCleanupPerAdminOverrides($mysqli, array_keys($settingsToSync));

    if (method_exists($mysqli, 'commit')) {
        $mysqli->commit();
    }
} catch (Throwable $throwable) {
    if (method_exists($mysqli, 'rollback')) {
        $mysqli->rollback();
    }
    releaseSyncErr('Sync failed: ' . $throwable->getMessage());
} finally {
    if (method_exists($mysqli, 'autocommit')) {
        $mysqli->autocommit(true);
    }
    $mysqli->close();
}

releaseSyncOut('Release settings synced successfully.');
releaseSyncOut('pubspec version: ' . $pubspecInfo['raw']);
releaseSyncOut('latest version: ' . $versionName);
releaseSyncOut('latest build: ' . $buildNumber);
releaseSyncOut('apk url: ' . $apkUrl);
if ($apkPath !== '') {
    releaseSyncOut('published apk: ' . $apkPath);
}
releaseSyncOut('force update: ' . ($forceUpdate ? '1' : '0'));
