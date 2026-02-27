<?php
// --- Bot A: auto send to Bot B ---
$payment_text = '$11.10 paid by YAV TOUCH (*327) on Oct 09, 08:43 PM via ABA PAY at SK CHHOUK MEAS. Trx. ID: 176001741041357, APV: 859589.';

// ប្រើ regex ដើម្បីយកតម្លៃទឹកលុយ
if (preg_match('/\$(\d+(?:\.\d{1,2})?)/', $payment_text, $m)) {
    $amount = floatval($m[1]);
} else {
    exit("No amount found\n");
}

$data = [
    'user_name' => 'YAV TOUCH',
    'amount' => $amount,
    'text' => $payment_text
];

// ផ្ញើទៅ Bot B webhook
$botB_url = "https://app.vvc.asia/demo-attendance/my_bot.php";

$ch = curl_init($botB_url);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/json']);
curl_exec($ch);
curl_close($ch);
?>
