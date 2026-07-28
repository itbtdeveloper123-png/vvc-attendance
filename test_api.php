<?php
/**
 * Simple API Test Script
 * Tests basic API connectivity and error handling
 */

// Test basic API connectivity
echo "Testing API Connectivity...\n";

// Test 1: Check if api.php exists and is readable
if (file_exists(__DIR__ . '/api.php')) {
    echo "✓ api.php file exists\n";
} else {
    echo "✗ api.php file not found\n";
    exit(1);
}

// Test 2: Check if config.php exists and is readable
if (file_exists(__DIR__ . '/config.php')) {
    echo "✓ config.php file exists\n";
} else {
    echo "✗ config.php file not found\n";
    exit(1);
}

// Test 3: Test database connection by including config
try {
    require_once __DIR__ . '/config.php';
    echo "✓ config.php loaded successfully\n";
    
    // Test database connection
    $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    if ($mysqli->connect_error) {
        echo "✗ Database connection failed: " . $mysqli->connect_error . "\n";
        exit(1);
    } else {
        echo "✓ Database connection successful\n";
        $mysqli->close();
    }
} catch (Exception $e) {
    echo "✗ Database connection error: " . $e->getMessage() . "\n";
    exit(1);
}

// Test 4: Check if required PHP extensions are available
$required_extensions = ['mysqli', 'json', 'mbstring'];
foreach ($required_extensions as $ext) {
    if (extension_loaded($ext)) {
        echo "✓ Extension '$ext' is loaded\n";
    } else {
        echo "✗ Extension '$ext' is not loaded\n";
    }
}

// Test 5: Check if uploads directory is writable
if (is_writable(__DIR__ . '/uploads')) {
    echo "✓ uploads directory is writable\n";
} else {
    echo "✗ uploads directory is not writable\n";
}

// Test 6: Test actual API endpoint with a simple request
echo "\nTesting API endpoint...\n";
try {
    // Simulate a simple API request
    $_POST['action'] = 'test';
    $_POST['employee_id'] = 'test123';
    
    // Capture the output
    ob_start();
    include __DIR__ . '/api.php';
    $output = ob_get_clean();
    
    echo "API Response: " . substr($output, 0, 200) . "...\n";
    
    if (strpos($output, 'success') !== false || strpos($output, 'error') !== false) {
        echo "✓ API endpoint responded\n";
    } else {
        echo "✗ API endpoint did not return expected JSON\n";
    }
} catch (Exception $e) {
    echo "✗ API endpoint test failed: " . $e->getMessage() . "\n";
}

echo "\nBasic API Test Completed!\n";
