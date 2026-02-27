<?php
// One-time BOM removal + self-delete script
// Access via: http://localhost/vvc-attendance/fix_bom.php
$file = __DIR__ . '/scan.php';
$content = file_get_contents($file);
$bom = "\xEF\xBB\xBF";

header('Content-Type: text/plain; charset=utf-8');

if (substr($content, 0, 3) === $bom) {
    $written = file_put_contents($file, substr($content, 3));
    if ($written !== false) {
        echo "✅ SUCCESS: BOM removed from scan.php ({$written} bytes written)\n";
        echo "First 6 bytes now: " . bin2hex(substr(file_get_contents($file), 0, 6)) . "\n";
    } else {
        echo "❌ FAIL: Could not write file. Check permissions.\n";
    }
} else {
    echo "ℹ️ No BOM found. First bytes: " . bin2hex(substr($content, 0, 3)) . " (already clean)\n";
}

// Self-delete after run
@unlink(__FILE__);
echo "\n🗑️ fix_bom.php deleted.\n";
