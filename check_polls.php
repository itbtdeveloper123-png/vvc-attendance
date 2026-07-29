<?php
// Simple script to check poll configuration
require_once 'config.php';

$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "=== Checking Poll Tables ===\n\n";

// Check if poll tables exist
$tables = ['poll_events', 'poll_candidates', 'poll_votes'];
foreach ($tables as $table) {
    $result = $mysqli->query("SHOW TABLES LIKE '$table'");
    echo ($result && $result->num_rows > 0) ? "✓ Table '$table' exists\n" : "✗ Table '$table' missing\n";
}

echo "\n=== Checking Active Polls ===\n\n";

// Check for active polls
$polls_query = "SELECT * FROM poll_events WHERE is_active = 1";
$result = $mysqli->query($polls_query);

if ($result && $result->num_rows > 0) {
    echo "Found {$result->num_rows} active poll(s):\n";
    while ($row = $result->fetch_assoc()) {
        echo "- ID: {$row['id']}, Title: {$row['title']}, Start: {$row['start_date']}, End: {$row['end_date']}\n";
        echo "  Allowed employees: " . ($row['allowed_employee_ids'] ?? 'NULL') . "\n";
        echo "  Excluded employees: " . ($row['excluded_employee_ids'] ?? 'NULL') . "\n";
    }
} else {
    echo "No active polls found\n";
}

echo "\n=== Checking Poll Candidates ===\n\n";

// Check for candidates
$candidates_query = "SELECT pc.*, pe.title as poll_title FROM poll_candidates pc 
                     LEFT JOIN poll_events pe ON pc.poll_id = pe.id";
$result = $mysqli->query($candidates_query);

if ($result && $result->num_rows > 0) {
    echo "Found {$result->num_rows} candidate(s):\n";
    while ($row = $result->fetch_assoc()) {
        echo "- Poll: {$row['poll_title']}, Employee ID: {$row['employee_id']}, Category: {$row['category']}\n";
    }
} else {
    echo "No candidates found\n";
}

echo "\n=== Checking App Settings for Poll Card Visibility ===\n\n";

// Check app_settings for poll_voting visibility
$settings_query = "SELECT * FROM app_settings WHERE setting_key LIKE '%poll_voting%'";
$result = $mysqli->query($settings_query);

if ($result && $result->num_rows > 0) {
    echo "Found {$result->num_rows} poll_voting setting(s):\n";
    while ($row = $result->fetch_assoc()) {
        echo "- Admin: {$row['admin_id']}, Key: {$row['setting_key']}, Value: {$row['setting_value']}\n";
    }
} else {
    echo "No poll_voting visibility settings found\n";
    echo "This might be the issue - the poll card may be hidden by default\n";
}

echo "\n=== Checking Current Date ===\n\n";
echo "Current date: " . date('Y-m-d') . "\n";

$mysqli->close();
?>