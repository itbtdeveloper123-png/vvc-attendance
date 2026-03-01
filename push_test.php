<?php
require 'config.php';
require 'webpush_functions.php';

$conn = new mysqli(DB_SERVER, DB_USERNAME, DB_PASSWORD, DB_NAME);
if ($conn->connect_error) die("Connection failed: " . $conn->connect_error);

$sql = "SELECT employee_id, COUNT(*) as count FROM push_subscriptions GROUP BY employee_id";
$res = $conn->query($sql);

echo "<h3>Check Push Subscriptions:</h3>";
if ($res->num_rows > 0) {
    while ($row = $res->fetch_assoc()) {
        echo "User: " . htmlspecialchars($row['employee_id']) . " has " . $row['count'] . " device(s) registered.<br>";
        if (isset($_GET['test']) && $_GET['test'] == $row['employee_id']) {
            echo "Sending test push to " . $row['employee_id'] . "... ";
            if (sendWebPushNotification($conn, $row['employee_id'], "តេស្ត!", "នេះជាសារសាកល្បងពីប្រព័ន្ធ។")) {
                echo "Success!<br>";
            } else {
                echo "Failed!<br>";
            }
        } else {
            echo " <a href='?test=" . urlencode($row['employee_id']) . "'>Send Test Push</a><br>";
        }
    }
} else {
    echo "No devices registered yet.";
}
$conn->close();
?>
