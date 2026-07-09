<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

require_once 'config.php';
require_once 'enterprise_helpers.php';

echo "<h3>Testing Google Roads API:</h3>";

$key = get_google_maps_api_key();
echo "Configured API Key: " . (empty($key) ? "EMPTY" : substr($key, 0, 8) . "...") . "<br/>";

// Test coordinates (Phnom Penh)
$points = [
    ['latitude' => 11.5564, 'longitude' => 104.9282],
    ['latitude' => 11.5569, 'longitude' => 104.9290]
];

$url = 'https://roads.googleapis.com/v1/snapToRoads?interpolate=true&path=11.5564,104.9282|11.5569,104.9290&key=' . rawurlencode($key);

echo "Calling URL: $url <br/><br/>";

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
$res = curl_exec($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

echo "HTTP Code: $http_code <br/>";
echo "Response: <pre>" . htmlspecialchars($res) . "</pre>";
?>
