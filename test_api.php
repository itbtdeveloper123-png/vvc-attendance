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
    // First test the simple PHP file
    $simpleTestUrl = 'https://app.vvc.asia/flutter/simple_test.php';
    
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $simpleTestUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        
        $simpleOutput = curl_exec($ch);
        $simpleHttpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $simpleError = curl_error($ch);
        curl_close($ch);
        
        if ($simpleError) {
            echo "✗ Simple PHP test failed: $simpleError\n";
        } else {
            echo "Simple PHP Test (HTTP $simpleHttpCode): $simpleOutput\n";
        }
    }
    
    // Now test the actual API endpoint with GET request first
    $testUrl = 'https://app.vvc.asia/flutter/api.php?action=test';
    
    if (function_exists('curl_init')) {
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $testUrl);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            echo "✗ GET Curl error: $error\n";
        } else {
            echo "API GET Test (HTTP $httpCode): " . substr($output, 0, 500) . "...\n";
            
            if ($httpCode === 200) {
                if (strpos($output, 'success') !== false) {
                    echo "✓ API GET endpoint responded correctly\n";
                } else {
                    echo "✗ API GET endpoint did not return expected JSON\n";
                }
            } else {
                echo "✗ API GET returned HTTP $httpCode instead of 200\n";
            }
        }
    }
    
    // Also test with POST
    $testUrlPost = 'https://app.vvc.asia/flutter/api.php';
    
    if (function_exists('curl_init')) {
        $data = [
            'action' => 'test',
            'employee_id' => 'test123'
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $testUrlPost);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        
        $output = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            echo "✗ POST Curl error: $error\n";
        } else {
            echo "API POST Test (HTTP $httpCode): " . substr($output, 0, 500) . "...\n";
            
            if ($httpCode === 200) {
                if (strpos($output, 'success') !== false) {
                    echo "✓ API POST endpoint responded correctly\n";
                } else {
                    echo "✗ API POST endpoint did not return expected JSON\n";
                }
            } else {
                echo "✗ API POST returned HTTP $httpCode instead of 200\n";
            }
        }
    } else {
        echo "✗ Curl not available, skipping endpoint test\n";
    }
} catch (Exception $e) {
    echo "✗ API endpoint test failed: " . $e->getMessage() . "\n";
}

echo "\nBasic API Test Completed!\n";
