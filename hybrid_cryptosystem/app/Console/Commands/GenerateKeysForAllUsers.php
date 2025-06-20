<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\User;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Storage;

class GenerateKeysForAllUsers extends Command
{
    protected $signature = 'generate:keys';
    protected $description = 'Generate RSA keypairs for all users without one';

    public function handle()
    {
        $users = User::all();

        foreach ($users as $user) {
            if (!$user->public_key || !$user->private_key) {
                $this->generateKeypair($user);
                $this->info("✅ Keypair generated for: " . $user->email);
            } else {
                $this->line("⏭️  Skipped (already has key): " . $user->email);
            }
        }

        $this->info("🔐 Keypair generation complete.");
    }

    private function generateKeypair($user)
    {
        $password = 'default123'; // You can replace this with user-specific logic

        $config = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privateKey, $password);

        $pubKeyDetails = openssl_pkey_get_details($res);
        $publicKey = $pubKeyDetails["key"];

        // Store in DB
        $user->public_key = $publicKey;
        $user->private_key = Crypt::encryptString($privateKey);
        $user->save();

        // Store as file (optional)
        Storage::put("keys/{$user->username}_private.pem", $privateKey);
        Storage::put("keys/{$user->username}_public.pem", $publicKey);
    }
}
