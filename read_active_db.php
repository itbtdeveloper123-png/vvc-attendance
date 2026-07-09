<?php
require_once 'config.php';
echo "<h3>Active Database Configuration on Server:</h3>";
echo "DB_SERVER: " . DB_SERVER . "<br/>";
echo "DB_NAME: " . DB_NAME . "<br/>";
echo "DB_USERNAME: " . DB_USERNAME . "<br/>";
echo "is_localhost: " . ($is_localhost ? 'TRUE' : 'FALSE') . "<br/>";
?>
