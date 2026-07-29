<?php
// Debug script to check why polls are not showing for mobile app
require_once 'config.php';

$mysqli = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);

if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
}

echo "<h2>=== Debug Poll Data ===</h2>";

// Get current date
$current_date = date('Y-m-d');
echo "<p>Current date: $current_date</p>";

// Check poll_events table
echo "<h3>1. Poll Events (Active)</h3>";
$polls_query = "SELECT * FROM poll_events WHERE is_active = 1";
$result = $mysqli->query($polls_query);

if ($result && $result->num_rows > 0) {
    echo "<p>Found {$result->num_rows} active poll(s):</p>";
    echo "<table border='1' cellpadding='5'>";
    echo "<tr><th>ID</th><th>Title</th><th>Start Date</th><th>End Date</th><th>Is Active</th><th>Allowed IDs</th><th>Excluded IDs</th></tr>";
    
    while ($row = $result->fetch_assoc()) {
        $start_ok = ($row['start_date'] <= $current_date) ? "✓" : "✗";
        $end_ok = ($row['end_date'] >= $current_date) ? "✓" : "✗";
        
        echo "<tr>";
        echo "<td>{$row['id']}</td>";
        echo "<td>{$row['title']}</td>";
        echo "<td>{$row['start_date']} $start_ok</td>";
        echo "<td>{$row['end_date']} $end_ok</td>";
        echo "<td>{$row['is_active']}</td>";
        echo "<td>" . ($row['allowed_employee_ids'] ?? 'NULL') . "</td>";
        echo "<td>" . ($row['excluded_employee_ids'] ?? 'NULL') . "</td>";
        echo "</tr>";
    }
    echo "</table>";
} else {
    echo "<p><strong>✗ No active polls found!</strong></p>";
}

// Check poll_candidates table
echo "<h3>2. Poll Candidates</h3>";
$candidates_query = "SELECT pc.*, pe.title as poll_title FROM poll_candidates pc 
                     LEFT JOIN poll_events pe ON pc.poll_id = pe.id";
$result = $mysqli->query($candidates_query);

if ($result && $result->num_rows > 0) {
    echo "<p>Found {$result->num_rows} candidate(s):</p>";
    echo "<table border='1' cellpadding='5'>";
    echo "<tr><th>Poll</th><th>Candidate ID</th><th>Employee ID</th><th>Category</th></tr>";
    
    while ($row = $result->fetch_assoc()) {
        echo "<tr>";
        echo "<td>{$row['poll_title']}</td>";
        echo "<td>{$row['id']}</td>";
        echo "<td>{$row['employee_id']}</td>";
        echo "<td>{$row['category']}</td>";
        echo "</tr>";
    }
    echo "</table>";
} else {
    echo "<p><strong>✗ No candidates found!</strong> This is likely the problem.</p>";
    echo "<p>Polls need candidates to be visible in the mobile app.</p>";
}

// Check which polls have candidates
echo "<h3>3. Polls with Candidates</h3>";
$polls_with_candidates = "SELECT pe.id, pe.title, COUNT(pc.id) as candidate_count 
                          FROM poll_events pe 
                          LEFT JOIN poll_candidates pc ON pe.id = pc.poll_id 
                          WHERE pe.is_active = 1 
                          GROUP BY pe.id, pe.title";
$result = $mysqli->query($polls_with_candidates);

if ($result && $result->num_rows > 0) {
    echo "<table border='1' cellpadding='5'>";
    echo "<tr><th>Poll ID</th><th>Title</th><th>Candidate Count</th><th>Status</th></tr>";
    
    while ($row = $result->fetch_assoc()) {
        $status = $row['candidate_count'] > 0 ? "✓ Visible" : "✗ Hidden (no candidates)";
        echo "<tr>";
        echo "<td>{$row['id']}</td>";
        echo "<td>{$row['title']}</td>";
        echo "<td>{$row['candidate_count']}</td>";
        echo "<td>$status</td>";
        echo "</tr>";
    }
    echo "</table>";
}

// Add a form to add candidates quickly
echo "<h3>4. Quick Add Candidate</h3>";
echo "<form method='POST'>";
echo "<label>Poll ID: <input type='text' name='poll_id' required></label><br><br>";
echo "<label>Employee ID: <input type='text' name='employee_id' required></label><br><br>";
echo "<label>Category: <input type='text' name='category' placeholder='Head Office, Store 318, etc.'></label><br><br>";
echo "<input type='submit' name='add_candidate' value='Add Candidate'>";
echo "</form>";

if (isset($_POST['add_candidate'])) {
    $poll_id = (int)$_POST['poll_id'];
    $employee_id = $mysqli->real_escape_string($_POST['employee_id']);
    $category = $mysqli->real_escape_string($_POST['category'] ?? 'Head Office');
    
    $insert = "INSERT INTO poll_candidates (poll_id, employee_id, category) VALUES ($poll_id, '$employee_id', '$category')";
    if ($mysqli->query($insert)) {
        echo "<p style='color: green;'>✓ Candidate added successfully!</p>";
    } else {
        echo "<p style='color: red;'>✗ Failed to add candidate: " . $mysqli->error . "</p>";
    }
}

$mysqli->close();
?>