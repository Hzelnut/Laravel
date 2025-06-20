<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;

class KeyController extends Controller
{
    /**
     * Download the currently authenticated user's private RSA key.
     */
    public function download()
    {
        $user = Auth::user();

        // Check if private key exists
        if (empty($user->private_key)) {
            return back()->withErrors(['private_key' => 'No private key found for your account.']);
        }

        // Try decrypting the private key
        try {
            $privateKey = Crypt::decryptString($user->private_key);
        } catch (\Exception $e) {
            return back()->withErrors(['private_key' => 'Failed to decrypt your private key.']);
        }

        $fileName = 'private_key_' . $user->id . '.pem';

        return response($privateKey, 200, [
            'Content-Type' => 'application/x-pem-file',
            'Content-Disposition' => "attachment; filename=\"$fileName\""
        ]);
    }
}
