<?php
// បង្ហាញ Error សម្រាប់ Debugging
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

//======================================================================
// ១. ការកំណត់ (CONFIGURATION)
//======================================================================

// ថូខឹនរបស់អ្នកផ្ញើសារ (យើងប្រើថូខឹនរបស់ Bot B ដើម្បីផ្ញើសារជូនដំណឹង)
define('SENDER_BOT_TOKEN', '8437133772:AAG_jvDhmYZVeWBVQTJIAfsMkDRLvWYqz-Y'); // <<<--- សូមដាក់ BOT TOKEN របស់ BOT B នៅទីនេះ

// ឈ្មោះឯកសារសម្រាប់រក្សាទុកទិន្នន័យបម្រុង
define('DATA_FILE_A', __DIR__ . '/data_a.json');

// បញ្ចូលឯកសារមុខងារសម្រាប់បញ្ជូនទិន្នន័យទៅ Bot B
require_once 'bot_a_handler.php';

//======================================================================
// ២. មុខងារជំនួយ (HELPER FUNCTIONS)
//======================================================================

function readDataA() { if (!file_exists(DATA_FILE_A) || filesize(DATA_FILE_A) === 0) { return []; } $json_data = file_get_contents(DATA_FILE_A); $data = json_decode($json_data, true); return is_array($data) ? $data : []; }
function writeDataA($data) { return file_put_contents(DATA_FILE_A, json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE)); }
function sendMessageToGroup($token, $chat_id, $text) { $url = "https://api.telegram.org/bot{$token}/sendMessage"; $params = ['chat_id' => $chat_id, 'text' => $text, 'parse_mode' => 'HTML']; $ch = curl_init(); curl_setopt($ch, CURLOPT_URL, $url); curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, $params); curl_setopt($ch, CURLOPT_RETURNTRANSFER, true); curl_exec($ch); curl_close($ch); }

//======================================================================
// ៣. ផ្នែកដំណើរការหลัก (MAIN LOGIC)
//======================================================================

// ជំហានទី១: ទទួលទិន្នន័យពិតពី Webhook (ឧ. ពី ABA)
$raw_webhook_data = file_get_contents('php://input');
file_put_contents('webhook_log.txt', date("Y-m-d H:i:s") . " - " . $raw_webhook_data . "\n\n", FILE_APPEND);
$data_from_webhook = json_decode($raw_webhook_data, true);

if ($data_from_webhook === null || !is_array($data_from_webhook)) {
    http_response_code(400); // Bad Request
    exit("Invalid data received.");
}

// ជំហានទី២: ទាញយកข้อมูลจาก Webhook ហើយสร้างเป็น Array តាមទម្រង់របស់យើង
// **សំខាន់:** អ្នកត្រូវកែប្រែ key ខាងក្រោមនេះ ឲ្យត្រូវនឹងទិន្នន័យពិតដែល ABA បញ្ជូនមក
$transaction_data = [
    'amount' => $data_from_webhook['amount'] ?? 'N/A',
    'currency' => $data_from_webhook['currency'] ?? 'USD',
    'payer_name' => $data_from_webhook['fromAccountName'] ?? 'Unknown',
    'payer_phone' => $data_from_webhook['fromAccount'] ?? 'Unknown',
    'trx_id' => $data_from_webhook['transactionId'] ?? 'N/A',
    'merchant_name' => $data_from_webhook['merchantName'] ?? 'N/A',
    'stand' => $data_from_webhook['merchantStand'] ?? 'N/A'
];

// ជំហានទី៣: រក្សាទុកទិន្នន័យចូលក្នុង data_a.json
$all_data_A = readDataA();
$new_transaction = $transaction_data;
$new_transaction['received_at'] = date('Y-m-d H:i:s');
$all_data_A[] = $new_transaction;

if (writeDataA($all_data_A)) {
    // ជំហានទី៤: បង្កើតសារជាអក្សរ
    $last_trx = end($all_data_A);
    $dynamicPaymentMessage = "Received {$last_trx['amount']} {$last_trx['currency']} from {$last_trx['payer_phone']} {$last_trx['payer_name']}. Ref.ID: {$last_trx['trx_id']}, at {$last_trx['merchant_name']}, STAND: {$last_trx['stand']}.";
    
    // ជំហានទី៥: ធ្វើកិច្ចការពីរព្រមគ្នា
    // ផ្ញើសារទៅ Group (ដោយប្រើថូខឹនរបស់ Bot B)
    sendMessageToGroup(SENDER_BOT_TOKEN, GROUP_CHAT_ID, $dynamicPaymentMessage);
    
    // បញ្ជូនទិន្នន័យទៅ Bot B ដើម្បីបូកសរុប
    triggerBotB($dynamicPaymentMessage);
    
    // ឆ្លើយតបទៅ Server របស់ ABA វិញថាเราได้รับข้อมูลហើយ
    http_response_code(200);
    echo "Transaction processed successfully.";
} else {
    // បើមានបញ្ហា แจ้งกลับទៅ ABA វិញ
    http_response_code(500);
    echo "Failed to save transaction data.";
}
?>