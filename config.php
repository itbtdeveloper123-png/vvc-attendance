<?php
date_default_timezone_set('Asia/Phnom_Penh');
// config.php - Central configuration with Auto-Environment Detection (.env)

/**
 * Simple .env loader
 */
function loadEnv($path) {
    if (!file_exists($path)) {
        return false;
    }

    $lines = file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        if (strpos(trim($line), '#') === 0) continue;

        if (strpos($line, '=') !== false) {
            list($name, $value) = explode('=', $line, 2);
            $name = trim($name);
            $value = trim($value);

            if (!array_key_exists($name, $_SERVER) && !array_key_exists($name, $_ENV)) {
                putenv(sprintf('%s=%s', $name, $value));
                $_ENV[$name] = $value;
                $_SERVER[$name] = $value;
            }
        }
    }
    return true;
}

// Load .env file
loadEnv(__DIR__ . '/.env');

if (!function_exists('is_php_function_disabled')) {
    function is_php_function_disabled($functionName)
    {
        $functionName = strtolower(trim((string) $functionName));
        if ($functionName === '') {
            return false;
        }

        $disabled = array_filter(array_map('trim', explode(',', (string) ini_get('disable_functions'))));
        foreach ($disabled as $item) {
            if (strtolower($item) === $functionName) {
                return true;
            }
        }

        return false;
    }
}

if (!function_exists('resolve_ffmpeg_binary_status')) {
    function resolve_ffmpeg_binary_status($configuredPath = null)
    {
        $configuredPath = trim((string) ($configuredPath ?? getenv('FFMPEG_BINARY') ?: ''));
        $shellAvailable = function_exists('shell_exec') && !is_php_function_disabled('shell_exec');
        $isWindows = strtoupper(substr(PHP_OS, 0, 3)) === 'WIN';
        $status = [
            'configured_path' => $configuredPath,
            'resolved_path' => '',
            'env_present' => ($configuredPath !== ''),
            'exists' => false,
            'executable' => false,
            'is_directory' => false,
            'wrong_platform_binary' => false,
            'shell_available' => $shellAvailable,
            'status' => 'error',
            'message' => 'FFMPEG_BINARY is not configured.',
            'candidate_paths' => [],
        ];

        if ($configuredPath === '') {
            return $status;
        }

        $candidates = [$configuredPath];
        if (@is_dir($configuredPath)) {
            $status['is_directory'] = true;
            $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'ffmpeg';
            $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'ffmpeg.exe';
            $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'ffmpeg';
            $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'ffmpeg.exe';
        }
        $candidates = array_values(array_unique(array_filter($candidates, static function ($value) {
            return trim((string) $value) !== '';
        })));
        $status['candidate_paths'] = $candidates;

        foreach ($candidates as $candidate) {
            if (!@file_exists($candidate)) {
                continue;
            }
            if (@is_dir($candidate)) {
                continue;
            }

            $status['exists'] = true;
            $resolved = @realpath($candidate);
            $status['resolved_path'] = is_string($resolved) && $resolved !== '' ? $resolved : $candidate;
            $status['wrong_platform_binary'] = (!$isWindows && preg_match('/\.exe$/i', (string) $candidate) === 1);
            $status['executable'] = @is_executable($candidate) || $isWindows;

            if ($status['wrong_platform_binary']) {
                $status['status'] = 'error';
                $status['executable'] = false;
                $status['message'] = 'A Windows ffmpeg.exe file was found on a Linux server. Upload the Linux ffmpeg binary instead.';
                return $status;
            }

            if ($status['executable']) {
                $status['status'] = 'ok';
                $status['message'] = $status['is_directory']
                    ? 'FFmpeg directory was detected and the binary inside it was resolved automatically.'
                    : 'FFmpeg binary is ready.';
            } else {
                $status['status'] = 'warning';
                $status['message'] = 'FFmpeg binary was found, but it is not executable yet.';
            }
            return $status;
        }

        if (@file_exists($configuredPath)) {
            $status['exists'] = true;
        }

        if ($status['is_directory']) {
            $status['message'] = 'FFMPEG_BINARY points to a directory. Point it to the ffmpeg binary file or keep this directory only if it contains ffmpeg inside it.';
        } else {
            $status['message'] = 'FFmpeg binary could not be found at the configured path.';
        }

        return $status;
    }
}

if (!function_exists('resolve_ffmpeg_binary_path')) {
    function resolve_ffmpeg_binary_path($configuredPath = null)
    {
        $status = resolve_ffmpeg_binary_status($configuredPath);
        return (string) ($status['resolved_path'] ?? '');
    }
}

// ===============================================
//          ENVIRONMENT DETECTION
// ===============================================
$is_localhost = (
    in_array($_SERVER['REMOTE_ADDR'] ?? '', ['127.0.0.1', '::1']) ||
    in_array($_SERVER['SERVER_NAME'] ?? '', ['localhost', '127.0.0.1', '::1']) ||
    (stripos($_SERVER['HTTP_HOST'] ?? '', 'localhost') !== false) ||
    (PHP_OS_FAMILY === 'Windows')
);

// If running on the live production domain, force it to hosting mode (not localhost)
if (stripos($_SERVER['HTTP_HOST'] ?? '', 'app.vvc.asia') !== false) {
    $is_localhost = false;
}

// ===============================================
//          DATABASE CONFIGURATION
// ===============================================
if ($is_localhost) {
    // Localhost Environment
    define('DB_SERVER',   getenv('LOCAL_DB_SERVER')   ?: 'localhost');
    define('DB_NAME',     getenv('LOCAL_DB_NAME')     ?: 'samann1_attendance_db');
    define('DB_USERNAME', getenv('LOCAL_DB_USERNAME') ?: 'root');
    define('DB_PASSWORD', getenv('LOCAL_DB_PASSWORD') ?: '');
} else {
    // Hosting Environment
    define('DB_SERVER',   getenv('HOST_DB_SERVER')   ?: 'localhost');
    define('DB_NAME',     getenv('HOST_DB_NAME')     ?: 'samann1_hrm_db');
    define('DB_USERNAME', getenv('HOST_DB_USERNAME') ?: 'samann1_hrm_db');
    define('DB_PASSWORD', getenv('HOST_DB_PASSWORD') ?: 'hrm_db!@#');
}

// ===============================================
//          HRM DATABASE CONFIGURATION (Same as Hosting)
// ===============================================
define('HRM_DB_SERVER',   DB_SERVER);
define('HRM_DB_NAME',     DB_NAME);
define('HRM_DB_USERNAME', DB_USERNAME);
define('HRM_DB_PASSWORD', DB_PASSWORD);

// ===============================================
//          TELEGRAM CONFIGURATION
// ===============================================
define('TELEGRAM_BOT_TOKEN', getenv('TELEGRAM_BOT_TOKEN') ?: '');
define('TELEGRAM_CHAT_ID',   getenv('TELEGRAM_CHAT_ID')   ?: '');

// ===============================================
//          OTHER SETTINGS
// ===============================================
define('DEFAULT_ADMIN_ID',       getenv('DEFAULT_ADMIN_ID')       ?: 'admin');
define('DEFAULT_ADMIN_PASSWORD', getenv('DEFAULT_ADMIN_PASSWORD') ?: 'adminpass');
define('EARTH_RADIUS_KM', 6371);
define('TOLERANCE', 100);

// ===============================================
//          PUSH NOTIFICATION VAPID KEYS
// ===============================================
define('VAPID_PUBLIC_KEY',  getenv('VAPID_PUBLIC_KEY')  ?: '');
define('VAPID_PRIVATE_KEY', getenv('VAPID_PRIVATE_KEY') ?: '');

// ===============================================
//          GOOGLE MAPS / ROADS
// ===============================================
define(
    'GOOGLE_MAPS_API_KEY',
    getenv('GOOGLE_MAPS_API_KEY') ?: 'AIzaSyBTlrKycJRtWAU7mRzlfrCEeC6GCWgQERA'
);

// ===============================================
//          AI PROVIDER SETTINGS
// ===============================================
define('AI_CHAT_PROVIDER', getenv('AI_CHAT_PROVIDER') ?: '');
define('AI_CHAT_MODEL', getenv('AI_CHAT_MODEL') ?: '');
define('AI_CHAT_REASONING_EFFORT', getenv('AI_CHAT_REASONING_EFFORT') ?: '');
define('OPENAI_API_KEY', getenv('OPENAI_API_KEY') ?: '');
define('GROQ_API_KEY', getenv('GROQ_API_KEY') ?: '');
define('GEMINI_API_KEY', getenv('GEMINI_API_KEY') ?: '');
define('POLLINATIONS_API_KEY', getenv('POLLINATIONS_API_KEY') ?: '');
define('GITHUB_TOKEN', getenv('GITHUB_TOKEN') ?: '');
define('MEETING_AI_WORKER_URL', getenv('MEETING_AI_WORKER_URL') ?: '');
define('MEETING_AI_WORKER_TOKEN', getenv('MEETING_AI_WORKER_TOKEN') ?: '');
define('MEETING_AI_WORKER_TIMEOUT', (int)(getenv('MEETING_AI_WORKER_TIMEOUT') ?: 600));
define('MEETING_AI_LOCAL_ONLY', getenv('MEETING_AI_LOCAL_ONLY') ?: '0');

if (session_status() !== PHP_SESSION_ACTIVE) {
    $currentSavePath = (string)ini_get('session.save_path');
    $needsFallback = false;
    if ($currentSavePath === '') {
        $needsFallback = true;
    } else {
        $firstPath = explode(PATH_SEPARATOR, $currentSavePath, 2)[0];
        if ($firstPath === '' || !is_dir($firstPath) || !is_writable($firstPath)) {
            $needsFallback = true;
        }
    }

    if ($needsFallback) {
        $fallback = __DIR__ . DIRECTORY_SEPARATOR . 'php_sessions';
        if (!is_dir($fallback)) {
            @mkdir($fallback, 0777, true);
        }
        if (is_dir($fallback) && is_writable($fallback)) {
            ini_set('session.save_path', $fallback);
        }
    }
    session_start();
}

?>
