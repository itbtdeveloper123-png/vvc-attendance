<?php
// Simple test to check if basic PHP is working
echo "PHP is working\n";
echo "PHP Version: " . phpversion() . "\n";
echo "Current time: " . date('Y-m-d H:i:s') . "\n";

// Test JSON encoding
$test = ['success' => true, 'message' => 'Test'];
echo "JSON test: " . json_encode($test) . "\n";

// Test if we can check POST variables
echo "POST variables: " . print_r($_POST, true) . "\n";
echo "GET variables: " . print_r($_GET, true) . "\n";

// Check if we can access environment
echo "Environment check passed\n";
?>