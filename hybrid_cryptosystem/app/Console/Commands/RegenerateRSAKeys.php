<?php

namespace App\Console\Commands;

use Illuminate\Console\Command;
use App\Models\User;
use Illuminate\Support\Facades\Crypt;

class RegenerateRSAKeys extends Command
{
    protected $signature = 'keys:regenerate';
    protected $description = 'Regenerate all user RSA keypairs to use standard unencrypted format';

    public function handle()
    {
        $this->info('🔐 Regenerating keypairs for all users...');

        $users = User::all();

        foreach ($users as $user) {
            $this->line("Regenerating keys for: {$user->email}");

            // Generate new keypair
            $keyConfig = [
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
                "private_key_bits" => 2048,
            ];

            $res = openssl_pkey_new($keyConfig);

            openssl_pkey_export($res, $privateKeyPem); // no passphrase

            $publicKeyPem = openssl_pkey_get_details($res)['key'];

            // Update database
            $user->public_key = $publicKeyPem;
            $user->private_key = Crypt::encryptString($privateKeyPem);
            $user->save();
        }

        $this->info("✅ Done regenerating all keypairs.");
    }
}
