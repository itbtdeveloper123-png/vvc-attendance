<?php
// Serve a valid Web App Manifest with correct headers and no BOM/whitespace before JSON
header('Content-Type: application/manifest+json; charset=utf-8');
// Prevent caching during development (you can relax this later)
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');

$manifest = [
  'name' => 'Attendance',
  'short_name' => 'Attendance',
  'description' => 'Employee attendance and request management',
  'start_url' => 'scan.php',
  'scope' => './',
  'display' => 'standalone',
  'orientation' => 'portrait',
  'background_color' => '#ffffff',
  'theme_color' => '#007aff',
  // Note: Point to whatever icons you actually host; these can be adjusted later
  'icons' => [
    [ 'src' => 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png', 'sizes' => '192x192', 'type' => 'image/png' ],
    [ 'src' => 'https://cdn-icons-png.flaticon.com/512/11693/11693253.png', 'sizes' => '512x512', 'type' => 'image/png', 'purpose' => 'any maskable' ],
  ]
];

echo json_encode($manifest, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
