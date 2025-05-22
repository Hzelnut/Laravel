<?php
$keyConfig = [
    "digest_alg" => "sha256",
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];

$res = openssl_pkey_new($keyConfig);
if (!$res) {
    die("Failed to generate RSA key. Error: " . openssl_error_string());
}

echo "RSA key generated successfully!";
