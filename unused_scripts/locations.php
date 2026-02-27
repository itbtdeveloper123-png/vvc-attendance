<?php
session_start();
require_once __DIR__ . '/config.php';
$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    die("Database Connection Failed: " . $mysqli->connect_error);
}

// ===============================================
//           CORE LOGIC
// ===============================================
$is_logged_in = isset($_SESSION['employee_id']);
$locations = [];
$error_message = '';

// --- CHECK LOGIN STATUS ---
if (!$is_logged_in) {
    header("location: index.php");
    exit;
}

// --- DATABASE LOGIC: FETCH LOCATIONS ---
$sql = "SELECT location_id, location_name, latitude, longitude, radius_m, address
        FROM workplaces 
        ORDER BY location_name ASC";

if ($stmt = $mysqli->prepare($sql)) {
    $stmt->execute();
    $result = $stmt->get_result();

    while ($row = $result->fetch_assoc()) {
        $locations[] = $row;
    }
    $stmt->close();
} else {
    $error_message = "កំហុសក្នុងការទាញយកទីតាំង: " . $mysqli->error;
}

$page_title = "បញ្ជីទីតាំងការងារ"; 
?>
<!DOCTYPE html>
<html lang="km">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, user-scalable=no">
    <title><?php echo $page_title; ?></title>
    <link href="https://fonts.googleapis.com/css2?family=Kantumruy+Pro:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        /* CSS Styles (រួមបញ្ចូលរចនាបថសំខាន់ៗ) */
        :root {
            --primary-color: #007AFF;
            --background-color: #F0F2F5;
            --card-background: #FFFFFF;
            --text-color: #1c1c1e;
            --text-light: #8a8a8e;
            --border-radius: 12px;
            --card-shadow: 0 4px 15px rgba(0, 0, 0, 0.06);
            --success-color: #34C759;
        }

        body {
            font-family: 'Kantumruy Pro', sans-serif;
            margin: 0;
            padding: 0;
            background-color: var(--background-color);
            color: var(--text-color);
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        .mobile-body {
            max-width: 480px;
            margin: 0 auto;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
            background-color: var(--card-background);
            box-shadow: var(--card-shadow);
        }

        .app-container {
            flex-grow: 1;
        }

        .app-header {
            background-color: var(--card-background);
            padding: 12px 20px;
            text-align: center;
            border-bottom: 1px solid #e5e5e5;
            position: sticky;
            top: 0;
            z-index: 100;
        }

        .header-title {
            margin: 0;
            font-size: 1.25em;
            font-weight: 600;
        }

        .app-main {
            padding: 20px;
            flex-grow: 1;
            padding-bottom: 100px; 
        }
        
        h2 {
            font-size: 1.6em;
            font-weight: 700;
            margin-top: 0;
            margin-bottom: 20px;
        }
        
        /* --- Location List Style --- */
        .location-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        
        .location-item {
            background-color: var(--card-background);
            border-radius: var(--border-radius);
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
            border-left: 5px solid var(--primary-color);
        }
        
        .location-item h3 {
            margin: 0 0 10px 0;
            font-size: 1.1em;
            font-weight: 600;
            color: var(--primary-color);
        }

        .location-detail p {
            margin: 4px 0;
            font-size: 0.9em;
            color: var(--text-color);
        }
        .location-detail strong {
             font-weight: 500;
             color: var(--text-light);
             margin-right: 5px;
             min-width: 60px;
             display: inline-block;
        }

        .empty-state {
            text-align: center;
            padding: 50px 20px;
            color: var(--text-light);
            font-style: italic;
        }
        
        /* --- Bottom Navigation Styles --- */
        .bottom-nav {
            position: fixed; bottom: 0; left: 50%; transform: translateX(-50%);
            width: 100%; max-width: 480px; height: 85px; background-color: var(--card-background);
            display: flex; justify-content: space-around; align-items: flex-start;
            padding-top: 10px; padding-bottom: calc(10px + env(safe-area-inset-bottom));
            box-shadow: 0 -5px 20px rgba(0, 0, 0, 0.08); border-top: 1px solid #e5e5e5; z-index: 1000;
        }
        .nav-item {
            display: flex; flex-direction: column; align-items: center; text-decoration: none;
            color: var(--text-light); transition: color 0.2s;
        }
        .nav-item svg { width: 26px; height: 26px; margin-bottom: 4px; }
        .nav-item span { font-size: 0.75em; font-weight: 500; }
        .nav-item.active { color: var(--primary-color); }

    </style>
</head>
<body class="mobile-body">
    <div class="app-container">
        <header class="app-header">
            <h1 class="header-title"><?php echo $page_title; ?></h1>
        </header>

        <main class="app-main">
            <h2>ទីតាំងដែលបានអនុញ្ញាត</h2>
            
            <?php if ($error_message): ?>
                <div class="alert alert-error"><?php echo htmlspecialchars($error_message); ?></div>
            <?php endif; ?>

            <?php if (!empty($locations)): ?>
                <ul class="location-list">
                    <?php foreach ($locations as $loc): ?>
                        <li class="location-item">
                            <h3><?php echo htmlspecialchars($loc['location_name']); ?></h3>
                            <div class="location-detail">
                                <p>
                                    <strong>អាសយដ្ឋាន:</strong> <?php echo htmlspecialchars($loc['address'] ?? 'N/A'); ?>
                                </p>
                                <p>
                                    <strong>កាំ (Radius):</strong> <?php echo number_format($loc['radius_m'] ?? 0, 0) . ' ម៉ែត្រ'; ?>
                                </p>
                                <p>
                                    <strong>Lat/Lon:</strong> <?php echo number_format($loc['latitude'] ?? 0, 5) . ', ' . number_format($loc['longitude'] ?? 0, 5); ?>
                                </p>
                            </div>
                        </li>
                    <?php endforeach; ?>
                </ul>
            <?php else: ?>
                <div class="empty-state">
                    មិនទាន់មានទីតាំងណាមួយត្រូវបានចុះឈ្មោះទេ។
                </div>
            <?php endif; ?>
        </main>
    </div>
    
    <?php
    $current_page = basename($_SERVER['PHP_SELF']);
    $active_home = ('index.php' == $current_page || 'scan.php' == $current_page) ? 'active' : '';
    $active_logs = ''; 
    $active_locations = ('locations.php' == $current_page) ? 'active' : ''; // ACTIVE HERE
    $active_more = ('more_info.php' == $current_page) ? 'active' : ''; 
    $active_profile = ('profile.php' == $current_page) ? 'active' : '';
    ?>
    
    <nav class="bottom-nav">
        <a href="scan.php" class="nav-item <?php echo $active_home; ?>" data-page="scan.php">
            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24"><path d="M10 20v-6h4v6h5v-8h3L12 3 2 12h3v8h5z"/></svg>
            <span>ទំព័រដើម</span>
        </a>
        <a href="scan.php?view=my-logs-view" class="nav-item <?php echo $active_logs; ?>" data-page="view_logs.php">
            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24"><path d="M14 2H6c-1.1 0-2 .9-2 2v16c0 1.1.9 2 2 2h12c1.1 0 2-.9 2-2V8l-6-6zm2 16H8v-2h8v2zm0-4H8v-2h8v2zm-3-5V3.5L18.5 9H13z"/></svg>
            <span>កំណត់ត្រា</span>
        </a>
        <a href="locations.php" class="nav-item <?php echo $active_locations; ?>" data-page="locations.php">
            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24"><path d="M12 2C8.13 2 5 5.13 5 9c0 5.25 7 13 7 13s7-7.75 7-13c0-3.87-3.13-7-7-7zm0 9.5a2.5 2.5 0 0 1 0-5 2.5 2.5 0 0 1 0 5z"/></svg>
            <span>ទីតាំង</span>
        </a>
        <a href="more_info.php" class="nav-item <?php echo $active_more; ?>" data-page="more_info.php">
            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24"><path d="M6 10c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm12 0c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2zm-6 0c-1.1 0-2 .9-2 2s.9 2 2 2 2-.9 2-2-.9-2-2-2z"/></svg>
            <span>ព័ត៌មាន​ទៀត</span>
        </a>
        <a href="profile.php" class="nav-item <?php echo $active_profile; ?>" data-page="profile.php">
            <svg xmlns="http://www.w3.org/2000/svg" fill="currentColor" viewBox="0 0 24 24"><path d="M12 12c2.21 0 4-1.79 4-4s-1.79-4-4-4-4 1.79-4 4 1.79 4 4 4zm0 2c-2.67 0-8 1.34-8 4v2h16v-2c0-2.66-5.33-4-8-4z"/></svg>
            <span>គណនី</span>
        </a>
    </nav>
</body>
</html>