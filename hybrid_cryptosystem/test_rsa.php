<?php

$config = [
    "private_key_bits" => 2048,
    "private_key_type" => OPENSSL_KEYTYPE_RSA,
];

$res = openssl_pkey_new($config);
if (!$res) {
    echo "Failed to generate RSA key. Error: " . openssl_error_string();
} else {
    echo "RSA key generated successfully.\n";
}
