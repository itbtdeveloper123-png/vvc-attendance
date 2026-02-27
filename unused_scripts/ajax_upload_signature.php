<?php
// ajax_upload_signature.php
session_start();
header('Content-Type: application/json');

// --- ត្រូវប្រាកដថា User បាន Login ---
if (!isset($_SESSION['employee_id'])) {
    echo json_encode(['success' => false, 'message' => 'User not authenticated. Please login again.']);
    exit;
}

// ហៅ Function processSignatureUpload ពី index.php
// វិធីនេះគឺដើម្បីឱ្យ function អាចใช้งานได้
@include_once 'scan.php';

// ពិនិត្យមើលថាតើ Function មានឬអត់
if (!function_exists('processSignatureUpload')) {
     echo json_encode(['success' => false, 'message' => 'Core processing function is missing.']);
     exit;
}

$employee_id = $_SESSION['employee_id'];
$response = ['success' => false, 'message' => 'Upload failed due to an unknown error.'];

if (isset($_FILES['signature_image'])) {
    // ពិនិត្យទំហំ File (ឧ. មិនឱ្យលើសពី 5MB)
    if ($_FILES['signature_image']['size'] > 5 * 1024 * 1024) {
        $response['message'] = 'Image file is too large. Maximum size is 5MB.';
    } else {
        $processed_path = processSignatureUpload($_FILES['signature_image'], $employee_id);

        if ($processed_path) {
            $response = [
                'success' => true,
                'message' => 'Background removed successfully!',
                'filePath' => $processed_path // បញ្ជូន Path ត្រឡប់ទៅវិញ
            ];
        } else {
            // Error អាចមកពី GD Library មិនមាន, ប្រភេទ File មិនត្រូវ, ឬរូបភាពមិនអាចដំណើរការបាន
            $response['message'] = 'Failed to process image. Please use a clear signature image with a plain background (JPG, PNG).';
        }
    }
} else {
    $response['message'] = 'No image file received.';
}

echo json_encode($response);
?>