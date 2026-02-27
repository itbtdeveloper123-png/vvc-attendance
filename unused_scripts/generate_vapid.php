<?php
require __DIR__ . '/vendor/autoload.php';
putenv("OPENSSL_CONF=C:/xampp/php/extras/ssl/openssl.cnf");
use Minishlink\WebPush\VAPID;

$keys = VAPID::createVapidKeys();
echo "Public Key: " . $keys['publicKey'] . "\n";
echo "Private Key: " . $keys['privateKey'] . "\n";
