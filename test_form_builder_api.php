<?php
// Simple API Test Script for Form Builder
// រត់ script នេះដើម្បីពិនិត្យថា Form Builder API ដំណើរការត្រឹមត្រូវឬទេ

header('Content-Type: text/html; charset=UTF-8');
ini_set('display_errors', 1);
error_reporting(E_ALL);

session_start();

echo "<h2>Form Builder API Test</h2>";
echo "<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .success { color: green; font-weight: bold; }
    .error { color: red; font-weight: bold; }
    .warning { color: orange; font-weight: bold; }
    .info { color: blue; }
    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
    pre { background: #f4f4f4; padding: 10px; border-radius: 5px; overflow-x: auto; }
</style>";

require_once __DIR__ . '/config.php';

// Test 1: Database Connection
echo "<div class='section'>";
echo "<h3>Test 1: Database Connection</h3>";

try {
    $mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
    
    if ($mysqli->connect_error) {
        echo "<div class='error'>❌ Database connection failed: " . htmlspecialchars($mysqli->connect_error) . "</div>";
        echo "<div>Server: <code>" . htmlspecialchars(DB_SERVER) . "</code></div>";
        echo "<div>Database: <code>" . htmlspecialchars(DB_NAME) . "</code></div>";
    } else {
        echo "<div class='success'>✅ Database connection successful</div>";
        echo "<div>Server: <code>" . htmlspecialchars(DB_SERVER) . "</code></div>";
        echo "<div>Database: <code>" . htmlspecialchars(DB_NAME) . "</code></div>";
        $mysqli->set_charset("utf8mb4");
    }
} catch (Exception $e) {
    echo "<div class='error'>❌ Database connection error: " . htmlspecialchars($e->getMessage()) . "</div>";
}
echo "</div>";

// Test 2: Required Tables
echo "<div class='section'>";
echo "<h3>Test 2: Required Tables</h3>";

if (isset($mysqli) && $mysqli && !$mysqli->connect_error) {
    $required_tables = ['form_templates', 'form_fields', 'form_submissions'];
    $all_exist = true;
    
    foreach ($required_tables as $table) {
        $result = $mysqli->query("SHOW TABLES LIKE '$table'");
        if ($result && $result->num_rows > 0) {
            echo "<div class='success'>✅ Table <code>$table</code> exists</div>";
        } else {
            echo "<div class='error'>❌ Table <code>$table</code> does NOT exist</div>";
            $all_exist = false;
        }
    }
    
    if (!$all_exist) {
        echo "<div class='warning'>⚠️ Some tables are missing. Please run: <code>mysql -u username -p database_name < form_builder_schema.sql</code></div>";
    }
} else {
    echo "<div class='error'>❌ Cannot check tables - no database connection</div>";
}
echo "</div>";

// Test 3: API Endpoint Test
echo "<div class='section'>";
echo "<h3>Test 3: API Endpoint Test</h3>";

$protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https://' : 'http://';
$api_url = $protocol . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . '/form_builder_api.php';
echo "<div>API URL: <code>$api_url</code></div>";

// Test get_templates
echo "<h4>Test 3.1: GET /form_builder_api.php?action=get_templates</h4>";
$test_url = $api_url . '?action=get_templates';

$ch = curl_init($test_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false); // Skip SSL verification for testing
curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
curl_close($ch);

if ($response !== false) {
    $headers = substr($response, 0, $header_size);
    $body = substr($response, $header_size);
    
    echo "<div class='success'>✅ API responded (HTTP $http_code)</div>";
    echo "<div>Response Headers:</div>";
    echo "<pre>" . htmlspecialchars($headers) . "</pre>";
    echo "<div>Response Body:</div>";
    echo "<pre>" . htmlspecialchars($body) . "</pre>";
    
    // Try to parse JSON
    $json_data = json_decode($body, true);
    if ($json_data !== null) {
        echo "<div class='success'>✅ Valid JSON response</div>";
        echo "<div>Success: " . ($json_data['success'] ? 'true' : 'false') . "</div>";
        echo "<div>Message: " . htmlspecialchars($json_data['message'] ?? 'N/A') . "</div>";
        if (isset($json_data['data'])) {
            echo "<div>Data Count: " . count($json_data['data']) . " templates</div>";
        }
    } else {
        echo "<div class='error'>❌ Invalid JSON response</div>";
    }
} else {
    echo "<div class='error'>❌ API failed to respond</div>";
    echo "<div>Error: " . htmlspecialchars(curl_error($ch)) . "</div>";
}
echo "</div>";

// Test 4: Sample Template Creation
echo "<div class='section'>";
echo "<h3>Test 4: Sample Template Creation</h3>";

if (isset($mysqli) && $mysqli && !$mysqli->connect_error) {
    // Check if we have any templates
    $result = $mysqli->query("SELECT COUNT(*) as count FROM form_templates");
    if ($result) {
        $row = $result->fetch_assoc();
        $count = $row['count'];
        
        if ($count == 0) {
            echo "<div class='warning'>⚠️ No templates found. Creating sample template...</div>";
            
            $insert = $mysqli->prepare("INSERT INTO form_templates (name, description, category, status, created_by) VALUES (?, ?, ?, ?, ?)");
            $name = 'Test Template';
            $description = 'This is a test template created by the test script';
            $category = 'request';
            $status = 'active';
            $created_by = 1;
            
            $insert->bind_param("ssssi", $name, $description, $category, $status, $created_by);
            
            if ($insert->execute()) {
                $template_id = $mysqli->insert_id;
                echo "<div class='success'>✅ Sample template created (ID: $template_id)</div>";
                
                // Add a sample field
                $field_insert = $mysqli->prepare("INSERT INTO form_fields (template_id, field_type, field_name, field_label, placeholder, required, display_order) VALUES (?, ?, ?, ?, ?, ?, ?)");
                $field_type = 'text';
                $field_name = 'sample_field';
                $field_label = 'Sample Field';
                $placeholder = 'Enter value';
                $required = true;
                $display_order = 1;
                
                $field_insert->bind_param("isssii", $template_id, $field_type, $field_name, $field_label, $placeholder, $required, $display_order);
                
                if ($field_insert->execute()) {
                    echo "<div class='success'>✅ Sample field added to template</div>";
                } else {
                    echo "<div class='error'>❌ Failed to add sample field: " . htmlspecialchars($mysqli->error) . "</div>";
                }
                
                $field_insert->close();
            } else {
                echo "<div class='error'>❌ Failed to create sample template: " . htmlspecialchars($mysqli->error) . "</div>";
            }
            
            $insert->close();
        } else {
            echo "<div class='success'>✅ Found $count existing template(s)</div>";
        }
    }
} else {
    echo "<div class='error'>❌ Cannot check templates - no database connection</div>";
}
echo "</div>";

// Test 5: Session Check
echo "<div class='section'>";
echo "<h3>Test 5: Session Check</h3>";

if (isset($_SESSION['admin_id'])) {
    echo "<div class='success'>✅ Admin session exists</div>";
    echo "<div>Admin ID: <code>" . htmlspecialchars($_SESSION['admin_id']) . "</code></div>";
    
    if (isset($_SESSION['is_super_admin'])) {
        echo "<div>Super Admin: <code>" . ($_SESSION['is_super_admin'] ? 'Yes' : 'No') . "</code></div>";
    }
} else {
    echo "<div class='warning'>⚠️ No admin session found</div>";
    echo "<div class='info'>ℹ️ You need to login to admin panel first</div>";
}
echo "</div>";

// Summary
echo "<div class='section'>";
echo "<h3>📋 Summary & Next Steps</h3>";

if (isset($mysqli) && $mysqli && !$mysqli->connect_error) {
    echo "<div class='success'>✅ Database connection is working</div>";
    
    // Check tables again for summary
    $tables_missing = false;
    foreach (['form_templates', 'form_fields', 'form_submissions'] as $table) {
        $result = $mysqli->query("SHOW TABLES LIKE '$table'");
        if (!$result || $result->num_rows == 0) {
            $tables_missing = true;
        }
    }
    
    if ($tables_missing) {
        echo "<div class='error'>❌ Some database tables are missing</div>";
        echo "<div class='warning'>⚠️ Run: <code>mysql -u username -p database_name < form_builder_schema.sql</code></div>";
    } else {
        echo "<div class='success'>✅ All required tables exist</div>";
    }
    
    echo "<div class='info'>ℹ️ Try opening: <a href='form_builder.php' target='_blank'>form_builder.php</a></div>";
    echo "<div class='info'>ℹ️ If issues persist, check browser console (F12) for JavaScript errors</div>";
} else {
    echo "<div class='error'>❌ Database connection is not working</div>";
    echo "<div class='warning'>⚠️ Check your database credentials in config.php</div>";
}

echo "</div>";

if (isset($mysqli) && $mysqli && !$mysqli->connect_error) {
    $mysqli->close();
}
?>