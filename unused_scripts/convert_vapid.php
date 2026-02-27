<?php
require __DIR__ . '/vendor/autoload.php';
use Minishlink\WebPush\VAPID;

$privateKeyPEM = '-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg9t8CytL5CzWUDbGi
Trr7KO54kfpVGme+nySjecH9MPahRANCAARgUlNo1ujpZPLZzIMv+FLKi2oyI91V
svkiwvAOB7MBSZBBbycmza0SjQGBti5BzPo0Cekw1XHCdai1E1uNU/oL
-----END PRIVATE KEY-----';

$details = VAPID::fromPem($privateKeyPEM);
echo "Public Key (Base64Url): " . $details['publicKey'] . "\n";
echo "Private Key (Base64Url): " . $details['privateKey'] . "\n";
