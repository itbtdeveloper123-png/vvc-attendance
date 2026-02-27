<?php
function base64url_encode($data) {
    return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
}

$pubPEM = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYFJTaNbo6WTy2cyDL/hSyotqMiPdVbL5IsLwDgezAUmQQW8nJs2tEo0BgbYuQcz6NAnpMNVxwnWotRNbjVP6Cw==";
$der = base64_decode($pubPEM);
// The public key starts after the header. For prime256v1, it's usually the last 65 bytes.
$pubKeyRaw = substr($der, -65);
echo "Public Key (Base64Url): " . base64url_encode($pubKeyRaw) . "\n";

$privPEM = "9t8CytL5CzWUDbGiTrr7KO54kfpVGme+nySjecH9MPah"; // This is not the full PEM, I'll extract it properly
// The private key in the PEM MIGH... is at a specific offset.
// Let's just use the direct hex/base64 if possible.
// In the PEM: ...BAQQg9t8CytL5CzWUDbGiTrr7KO54kfpVGme+nySjecH9MPah...
// The private key is the 32 bytes: 9t8CytL5CzWUDbGiTrr7KO54kfpVGme+nySjecH9MPah
// Wait, that's already base64-ish.
$privRaw = base64_decode("9t8CytL5CzWUDbGiTrr7KO54kfpVGme+nySjecH9MPah");
echo "Private Key (Base64Url): " . base64url_encode($privRaw) . "\n";
