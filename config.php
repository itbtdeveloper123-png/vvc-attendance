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
            'install_steps' => [],
        ];

        // Build a list of candidates:
        // 1) explicit config + sub-paths inside it if directory
        // 2) PHP's PATH environment via where/which (if shell available)
        // 3) common install directories on Windows (Program Files, scoop, choco, xampp)
        // 4) common install directories on Linux (apt, snap, brew, /usr/local)
        $candidates = [];
        if ($configuredPath !== '') {
            $candidates[] = $configuredPath;
            if (@is_dir($configuredPath)) {
                $status['is_directory'] = true;
                $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'ffmpeg';
                $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'ffmpeg.exe';
                $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'ffmpeg';
                $candidates[] = rtrim($configuredPath, "/\\") . DIRECTORY_SEPARATOR . 'bin' . DIRECTORY_SEPARATOR . 'ffmpeg.exe';
            }
        }

        // 2) PATH probe via shell (platform-safe fallback, no shell_exec output dependence)
        if ($shellAvailable) {
            if ($isWindows) {
                $wherePath = rtrim((string) @shell_exec('where.exe ffmpeg 2>NUL'));
                if ($wherePath !== '') {
                    foreach (explode("\n", str_replace("\r", "\n", $wherePath)) as $ln) {
                        $ln = trim($ln);
                        if ($ln !== '') $candidates[] = $ln;
                    }
                }
            } else {
                $whichPath = rtrim((string) @shell_exec('command -v ffmpeg 2>/dev/null'));
                if ($whichPath !== '') $candidates[] = $whichPath;
            }
        }

        // 3) Common Windows paths
        if ($isWindows) {
            $pf = (string) (getenv('ProgramFiles') ?: 'C:\\Program Files');
            $pfx86 = (string) (getenv('ProgramFiles(x86)') ?: 'C:\\Program Files (x86)');
            $pd = (string) (getenv('ProgramData') ?: 'C:\\ProgramData');
            $up = (string) (getenv('USERPROFILE') ?: 'C:\\Users\\Public');
            $sysDrive = (string) (getenv('SystemDrive') ?: 'C:');
            $candidates[] = $pf . '\\FFmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $pf . '\\ffmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $pf . '\\FFmpeg\\ffmpeg.exe';
            $candidates[] = $pfx86 . '\\FFmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $pfx86 . '\\ffmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $pd . '\\chocolatey\\bin\\ffmpeg.exe';
            $candidates[] = $sysDrive . '\\ffmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $sysDrive . '\\ffmpeg\\ffmpeg.exe';
            $candidates[] = $up . '\\scoop\\shims\\ffmpeg.exe';
            $candidates[] = $up . '\\scoop\\apps\\ffmpeg\\current\\bin\\ffmpeg.exe';
            $candidates[] = $sysDrive . '\\xampp\\apache\\bin\\ffmpeg.exe';
            $candidates[] = $sysDrive . '\\xampp\\php\\ffmpeg.exe';
            $candidates[] = $sysDrive . '\\xampp\\mysql\\bin\\ffmpeg.exe';
            $candidates[] = $pf . '\\Gyan\\FFmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $pf . '\\BuildTools\\ffmpeg\\bin\\ffmpeg.exe';
            // winget: Gyan.FFmpeg, BtbN.FFmpeg
            $candidates[] = $up . '\\AppData\\Local\\Microsoft\\WinGet\\Packages\\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\\ffmpeg\\bin\\ffmpeg.exe';
            $candidates[] = $up . '\\AppData\\Local\\Microsoft\\WinGet\\Packages\\BtbN.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\\ffmpeg\\bin\\ffmpeg.exe';
        } else {
            // 4) Common Unix paths
            $candidates[] = '/usr/bin/ffmpeg';
            $candidates[] = '/usr/local/bin/ffmpeg';
            $candidates[] = '/opt/homebrew/bin/ffmpeg';
            $candidates[] = '/home/linuxbrew/.linuxbrew/bin/ffmpeg';
            $candidates[] = '/snap/bin/ffmpeg';
            $candidates[] = '/app/bin/ffmpeg';
            $candidates[] = '/usr/bin/vendor_perl/ffmpeg';
        }

        $candidates = array_values(array_unique(array_filter($candidates, static function ($value) {
            return trim((string) $value) !== '';
        })));
        $status['candidate_paths'] = $candidates;

        $installSteps = [];
        if ($isWindows) {
            $installSteps = [
                'title' => 'ដំឡើង FFmpeg លើ Windows',
                'steps' => [
                    'វិធីទី ១ (លឿនបំផុត)៖ បើក PowerShell រង្វាស់ Administrator រួចរត់៖ winget install --id Gyan.FFmpeg -e --accept-source-agreements --accept-package-agreements',
                    'វិធីទី ២៖ បើកម៉ឺនុយ Chocolatey៖ choco install ffmpeg -y',
                    'វិធីទី ៣៖ បើកម៉ឺនុយ Scoop៖ scoop install ffmpeg',
                    'វិធីទី ៤ (ដោយដៃ)៖ ទៅ https://www.gyan.dev/ffmpeg/builds/ → ទាញយក ffmpeg-release-essentials.zip → ដកហូតដាក់ C:\\ffmpeg បន្ទាប់មកបន្ថែម C:\\ffmpeg\\bin ទៅក្នុង System PATH របស់ Windows។',
                    'បន្ទាប់ពីដំឡើង រួចរត់៖ ffmpeg -version ដើម្បីផ្ទៀងផ្ទាត់។ បើមិនដំណើរទេ សូម set FFMPEG_BINARY=C:\\ffmpeg\\bin\\ffmpeg.exe ក្នុង file .env របស់គម្រោង។',
                ],
            ];
        } else {
            $osStr = PHP_OS;
            if (stripos($osStr, 'LINUX') !== false) {
                $installSteps = [
                    'title' => 'Install FFmpeg (Linux)',
                    'steps' => [
                        'Debian/Ubuntu: sudo apt update && sudo apt install -y ffmpeg',
                        'RHEL/CentOS/Rocky: sudo dnf install -y ffmpeg',
                        'Fedora: sudo dnf install -y ffmpeg',
                        'Arch: sudo pacman -S --noconfirm ffmpeg',
                        'Snap: sudo snap install ffmpeg',
                        'Set FFMPEG_BINARY=/usr/bin/ffmpeg ក្នុង .env ប្រសិនបើ PATH មិនមែនជាអថេរ។',
                    ],
                ];
            } elseif (stripos($osStr, 'DARWIN') !== false) {
                $installSteps = [
                    'title' => 'Install FFmpeg (macOS)',
                    'steps' => [
                        'Homebrew: brew install ffmpeg',
                        'MacPorts: sudo port install ffmpeg',
                        'Set FFMPEG_BINARY=/opt/homebrew/bin/ffmpeg ក្នុង .env ប្រសិនបើ Apple Silicon',
                    ],
                ];
            } else {
                $installSteps = [
                    'title' => 'Install FFmpeg',
                    'steps' => [
                        'ដំឡើង ffmpeg តាម package manager របស់ OS របស់អ្នក។',
                        'បន្ទាប់មកដាក់ path ពេញលេញទៅ FFMPEG_BINARY ក្នុង file .env',
                    ],
                ];
            }
        }
        $status['install_steps'] = $installSteps;

        // Scan candidates
        $lastDirCandidate = null;
        foreach ($candidates as $candidate) {
            if (!@file_exists($candidate)) {
                if (@is_dir($candidate)) $lastDirCandidate = $candidate;
                continue;
            }
            if (@is_dir($candidate)) {
                $lastDirCandidate = $candidate;
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

        if ($configuredPath !== '' && @file_exists($configuredPath)) {
            $status['exists'] = true;
        }

        if ($lastDirCandidate !== null && $configuredPath === '') {
            // keep best-effort
        }

        if ($configuredPath === '') {
            $status['message'] = $isWindows
                ? 'FFmpeg មិនទាន់បានដំឡើងនៅលើ Windows នោះទេ។ សូមធ្វើតាមជំហាន install_steps ដើម្បីដំឡើង។'
                : 'FFmpeg is not installed on this server yet. Please install the ffmpeg package.';
        } elseif ($status['is_directory']) {
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
    // Only start session if headers not yet sent (prevents "headers already sent" warning in API context)
    if (!headers_sent()) {
        @session_start();
    }
}

?>
