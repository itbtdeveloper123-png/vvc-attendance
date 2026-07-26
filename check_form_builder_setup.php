<?php
// Form Builder Setup Check Script
// រត់ script នេះដើម្បីពិនិត្យថា Form Builder ត្រូវបាន setup ត្រឹមត្រូវឬទេ

header('Content-Type: text/html; charset=UTF-8');
ini_set('display_errors', 1);
error_reporting(E_ALL);

require_once __DIR__ . '/config.php';

echo "<h2>Form Builder Setup Check</h2>";
echo "<style>
    body { font-family: Arial, sans-serif; margin: 20px; }
    .success { color: green; font-weight: bold; }
    .error { color: red; font-weight: bold; }
    .warning { color: orange; font-weight: bold; }
    .info { color: blue; }
    .section { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 5px; }
    code { background: #f4f4f4; padding: 2px 5px; border-radius: 3px; }
</style>";

// Database connection
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    echo "<div class='error'>❌ Database connection failed: " . htmlspecialchars($mysqli->connect_error) . "</div>";
    exit;
}

$mysqli->set_charset("utf8mb4");
echo "<div class='success'>✅ Database connected successfully</div>";

echo "<div class='success'>✅ Database connected successfully</div>";

// Check 1: Database Tables
echo "<div class='section'>";
echo "<h3>1. Database Tables Check</h3>";

$required_tables = ['form_templates', 'form_fields', 'form_submissions'];
foreach ($required_tables as $table) {
    $result = $mysqli->query("SHOW TABLES LIKE '$table'");
    if ($result && $result->num_rows > 0) {
        echo "<div class='success'>✅ Table <code>$table</code> exists</div>";
    } else {
        echo "<div class='error'>❌ Table <code>$table</code> does NOT exist</div>";
    }
}
echo "</div>";

// Check 2: Sidebar Settings
echo "<div class='section'>";
echo "<h3>2. Sidebar Settings Check</h3>";

$result = $mysqli->query("SELECT * FROM sidebar_settings WHERE menu_key = 'form_builder'");
if ($result && $result->num_rows > 0) {
    $row = $result->fetch_assoc();
    echo "<div class='success'>✅ Form Builder sidebar setting exists</div>";
    echo "<div>Menu Key: <code>" . htmlspecialchars($row['menu_key']) . "</code></div>";
    echo "<div>Menu Text: <code>" . htmlspecialchars($row['menu_text']) . "</code></div>";
    echo "<div>Icon: <code>" . htmlspecialchars($row['icon_class']) . "</code></div>";
    echo "<div>Order: <code>" . htmlspecialchars($row['menu_order']) . "</code></div>";
} else {
    echo "<div class='error'>❌ Form Builder sidebar setting does NOT exist</div>";
    echo "<div class='warning'>⚠️ Trying to add it now...</div>";
    
    $insert = $mysqli->prepare("INSERT INTO sidebar_settings (menu_key, menu_text, icon_class, menu_order) VALUES (?, ?, ?, ?)");
    $menu_key = 'form_builder';
    $menu_text = 'Form Builder';
    $icon_class = 'fa-solid fa-wand-magic-sparkles';
    $menu_order = 42;
    
    $insert->bind_param("sssi", $menu_key, $menu_text, $icon_class, $menu_order);
    if ($insert->execute()) {
        echo "<div class='success'>✅ Form Builder sidebar setting added successfully</div>";
    } else {
        echo "<div class='error'>❌ Failed to add sidebar setting: " . $mysqli->error . "</div>";
    }
}
echo "</div>";

// Check 3: Sample Templates
echo "<div class='section'>";
echo "<h3>3. Sample Templates Check</h3>";

$result = $mysqli->query("SELECT COUNT(*) as count FROM form_templates");
if ($result) {
    $row = $result->fetch_assoc();
    $count = $row['count'];
    if ($count > 0) {
        echo "<div class='success'>✅ Found $count template(s) in database</div>";
        
        // Show templates
        $templates = $mysqli->query("SELECT id, name, category, status FROM form_templates");
        if ($templates) {
            echo "<table border='1' style='border-collapse: collapse; margin-top: 10px;'>";
            echo "<tr><th>ID</th><th>Name</th><th>Category</th><th>Status</th></tr>";
            while ($template = $templates->fetch_assoc()) {
                echo "<tr>";
                echo "<td>" . htmlspecialchars($template['id']) . "</td>";
                echo "<td>" . htmlspecialchars($template['name']) . "</td>";
                echo "<td>" . htmlspecialchars($template['category']) . "</td>";
                echo "<td>" . htmlspecialchars($template['status']) . "</td>";
                echo "</tr>";
            }
            echo "</table>";
        }
    } else {
        echo "<div class='warning'>⚠️ No templates found in database</div>";
        echo "<div class='info'>ℹ️ Sample templates should be created by the schema import</div>";
    }
}
echo "</div>";

// Check 4: Current Admin
echo "<div class='section'>";
echo "<h3>4. Current Admin Session</h3>";

session_start();
if (isset($_SESSION['admin_id'])) {
    echo "<div class='success'>✅ Admin logged in</div>";
    echo "<div>Admin ID: <code>" . htmlspecialchars($_SESSION['admin_id']) . "</code></div>";
    
    if (isset($_SESSION['is_super_admin'])) {
        echo "<div>Super Admin: <code>" . ($_SESSION['is_super_admin'] ? 'Yes' : 'No') . "</code></div>";
    }
} else {
    echo "<div class='warning'>⚠️ No admin session found</div>";
    echo "<div class='info'>ℹ️ You need to login to admin panel first</div>";
}
echo "</div>";

// Check 5: File Existence
echo "<div class='section'>";
echo "<h3>5. File Existence Check</h3>";

$required_files = [
    'form_builder.php' => 'Form Builder UI',
    'form_builder_api.php' => 'Form Builder API',
    'form_builder_schema.sql' => 'Database Schema'
];

foreach ($required_files as $file => $description) {
    if (file_exists(__DIR__ . '/' . $file)) {
        echo "<div class='success'>✅ $description (<code>$file</code>) exists</div>";
    } else {
        echo "<div class='error'>❌ $description (<code>$file</code>) does NOT exist</div>";
    }
}
echo "</div>";

// Check 6: API Test
echo "<div class='section'>";
echo "<h3>6. API Test</h3>";

$api_url = 'http://' . $_SERVER['HTTP_HOST'] . dirname($_SERVER['PHP_SELF']) . '/form_builder_api.php';
echo "<div>Testing API: <code>$api_url</code></div>";

$test_data = [
    'action' => 'get_templates'
];

$ch = curl_init($api_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($test_data));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 10);

$response = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

if ($response !== false) {
    echo "<div class='success'>✅ API responded (HTTP $http_code)</div>";
    echo "<div>Response: <pre>" . htmlspecialchars(substr($response, 0, 500)) . "</pre></div>";
} else {
    echo "<div class='error'>❌ API failed to respond</div>";
}
echo "</div>";

// Summary
echo "<div class='section'>";
echo "<h3>📋 Summary</h3>";
echo "<div class='info'>ℹ️ If all checks pass, try clearing your browser cache and reloading the admin panel.</div>";
echo "<div class='info'>ℹ️ If sidebar setting was missing, it should be added now. Try refreshing the page.</div>";
echo "<div class='warning'>⚠️ If database tables are missing, run: <code>mysql -u username -p database_name < form_builder_schema.sql</code></div>";
echo "</div>";

$mysqli->close();
?>
