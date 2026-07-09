<?php
$env_path = __DIR__ . '/.env';
if (file_exists($env_path)) {
    echo "<h3>Server .env File Content:</h3><pre>";
    $lines = file($env_path);
    foreach ($lines as $line) {
        // Censor passwords for security
        if (stripos($line, 'PASSWORD') !== false) {
            $parts = explode('=', $line, 2);
            echo $parts[0] . "=********\n";
        } else {
            echo $line;
        }
    }
    echo "</pre>";
} else {
    echo "No .env file found in: " . __DIR__;
}
?>
