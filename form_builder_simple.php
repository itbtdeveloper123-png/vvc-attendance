<?php
// Simplified Form Builder - For Testing Without Session
// This version doesn't require admin session to load

if (!headers_sent()) {
    header('Content-Type: text/html; charset=UTF-8');
}
ini_set('default_charset', 'UTF-8');
mb_internal_encoding('UTF-8');

try {
    require_once __DIR__ . '/config.php';
} catch (Exception $e) {
    die('Error loading config: ' . $e->getMessage());
}

$page_title = 'Form Builder - កម្មវិធីបង្កើតសំណើ (Test Version)';
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo htmlspecialchars($page_title); ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Koulen&family=Battambang:wght@100;300;400;700;900&family=Kantumruy+Pro:ital,wght@0,100..700;1,100..700&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Battambang', sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            color: #333;
        }
        
        .header {
            background: white;
            padding: 20px 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .header h1 {
            font-family: 'Koulen', cursive;
            font-size: 28px;
            color: #667eea;
        }
        
        .container {
            display: flex;
            height: calc(100vh - 80px);
            padding: 20px;
            gap: 20px;
        }
        
        .main-content {
            flex: 1;
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        
        .info-box {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
        }
        
        .info-box h2 {
            font-family: 'Koulen', cursive;
            color: #667eea;
            margin-bottom: 15px;
        }
        
        .info-box p {
            margin-bottom: 10px;
        }
        
        .info-box ul {
            margin-left: 20px;
        }
        
        .info-box li {
            margin-bottom: 8px;
        }
        
        .success {
            color: green;
            font-weight: bold;
        }
        
        .error {
            color: red;
            font-weight: bold;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Form Builder - Test Version</h1>
    </div>
    
    <div class="container">
        <div class="main-content">
            <div class="info-box">
                <h2>📋 System Information</h2>
                <p><strong>PHP Version:</strong> <?php echo PHP_VERSION; ?></p>
                <p><strong>Server Time:</strong> <?php echo date('Y-m-d H:i:s'); ?></p>
                <p><strong>Charset:</strong> UTF-8</p>
                <p><strong>mbstring Extension:</strong> <?php echo extension_loaded('mbstring') ? '<span class="success">✅ Enabled</span>' : '<span class="error">❌ Disabled</span>'; ?></p>
                <p><strong>mysqli Extension:</strong> <?php echo extension_loaded('mysqli') ? '<span class="success">✅ Enabled</span>' : '<span class="error">❌ Disabled</span>'; ?></p>
            </div>
            
            <div class="info-box">
                <h2>🔧 Debugging Information</h2>
                <p>This is a simplified version of Form Builder without session requirements.</p>
                <ul>
                    <li>If this page loads successfully, the issue is with session authentication.</li>
                    <li>If this page fails, the issue is with PHP configuration or missing dependencies.</li>
                    <li>The full Form Builder requires admin session from admin_attendance.php</li>
                </ul>
            </div>
            
            <div class="info-box">
                <h2>🚀 Next Steps</h2>
                <ol>
                    <li>If this page loads: Try accessing Form Builder through admin panel</li>
                    <li>If this page fails: Check PHP error logs for specific error message</li>
                    <li>Contact admin panel to login, then access Form Builder from sidebar</li>
                </ol>
            </div>
        </div>
    </div>
</body>
</html>