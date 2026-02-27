<?php
$config = array(
    "private_key_bits" => 4096,
    "private_key_type" => OPENSSL_KEYTYPE_EC,
    "curve_name" => 'prime256v1',
    "config" => "C:/xampp/php/extras/ssl/openssl.cnf"
);
$res = openssl_pkey_new($config);
if (!$res) {
    while ($msg = openssl_error_string()) echo $msg . "\n";
    exit;
}
openssl_pkey_export($res, $privKey, NULL, $config);
$pubKey = openssl_pkey_get_details($res);
$pubKey = $pubKey["key"];

echo "Private Key (PEM):\n" . $privKey . "\n";
echo "Public Key (PEM):\n" . $pubKey . "\n";
