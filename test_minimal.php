<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);

echo "<h3>Testing connection to samann1_hrm_db:</h3>";

try {
    $conn = @mysqli_connect('127.0.0.1', 'samann1_hrm_db', 'hrm_db!@#', 'samann1_hrm_db');
    if (!$conn) {
        echo "Procedural connection failed (127.0.0.1): " . mysqli_connect_error() . "<br/>";
    } else {
        echo "Procedural connected successfully!<br/>";
        mysqli_close($conn);
    }
} catch (Throwable $e) {
    echo "Caught 127.0.0.1 connection exception: " . $e->getMessage() . " on line " . $e->getLine() . "<br/>";
}

try {
    $conn = @mysqli_connect('localhost', 'samann1_hrm_db', 'hrm_db!@#', 'samann1_hrm_db');
    if (!$conn) {
        echo "Procedural connection failed (localhost): " . mysqli_connect_error() . "<br/>";
    } else {
        echo "Procedural connected successfully!<br/>";
        mysqli_close($conn);
    }
} catch (Throwable $e) {
    echo "Caught localhost connection exception: " . $e->getMessage() . " on line " . $e->getLine() . "<br/>";
}
?>
