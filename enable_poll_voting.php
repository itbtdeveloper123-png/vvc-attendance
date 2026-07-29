<?php
// Script to enable poll voting card visibility for all roles
require_once 'config.php';

$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "=== Enabling Poll Voting Card Visibility ===\n\n";

$roles = ['skill', 'worker', 'hrm', 'admin'];
$enabled_count = 0;

foreach ($roles as $role) {
    $setting_key = "show_poll_voting_card__{$role}";
    
    // Check if setting exists
    $check_query = "SELECT * FROM app_settings WHERE setting_key = '$setting_key' AND admin_id = 'SYSTEM_WIDE'";
    $result = $mysqli->query($check_query);
    
    if ($result && $result->num_rows > 0) {
        // Update existing setting
        $update_query = "UPDATE app_settings SET setting_value = '1' WHERE setting_key = '$setting_key' AND admin_id = 'SYSTEM_WIDE'";
        if ($mysqli->query($update_query)) {
            echo "✓ Updated existing setting for role: $role\n";
            $enabled_count++;
        } else {
            echo "✗ Failed to update setting for role: $role - " . $mysqli->error . "\n";
        }
    } else {
        // Insert new setting
        $insert_query = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('SYSTEM_WIDE', '$setting_key', '1')";
        if ($mysqli->query($insert_query)) {
            echo "✓ Created new setting for role: $role\n";
            $enabled_count++;
        } else {
            echo "✗ Failed to create setting for role: $role - " . $mysqli->error . "\n";
        }
    }
}

echo "\n=== Summary ===\n";
echo "Enabled poll voting card for $enabled_count role(s)\n";

// Also check for individual admin settings
echo "\n=== Checking Individual Admin Settings ===\n";
$admin_check_query = "SELECT DISTINCT admin_id FROM app_settings WHERE admin_id != 'SYSTEM_WIDE'";
$admin_result = $mysqli->query($admin_check_query);

if ($admin_result && $admin_result->num_rows > 0) {
    while ($admin_row = $admin_result->fetch_assoc()) {
        $admin_id = $admin_row['admin_id'];
        echo "Found admin: $admin_id\n";
        
        foreach ($roles as $role) {
            $setting_key = "show_poll_voting_card__{$role}";
            $check_query = "SELECT * FROM app_settings WHERE setting_key = '$setting_key' AND admin_id = '$admin_id'";
            $result = $mysqli->query($check_query);
            
            if ($result && $result->num_rows == 0) {
                // Insert setting for this admin
                $insert_query = "INSERT INTO app_settings (admin_id, setting_key, setting_value) VALUES ('$admin_id', '$setting_key', '1')";
                if ($mysqli->query($insert_query)) {
                    echo "  ✓ Created setting for admin $admin_id, role: $role\n";
                }
            }
        }
    }
}

$mysqli->close();
echo "\nDone! Poll voting card should now be visible in the mobile app.\n";
?>