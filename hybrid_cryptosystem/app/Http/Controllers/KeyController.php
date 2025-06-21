<?php

namespace App\Http\Controllers;

use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Response;

class KeyController extends Controller
{
    public function download()
    {
        $user = Auth::user();

        if (!$user->private_key) {
            return back()->with('error', 'No private key found.');
        }

        $privateKey = Crypt::decryptString($user->private_key);
        $fileName = 'private_key_' . $user->id . '.pem';

        return response($privateKey, 200, [
            'Content-Type' => 'application/x-pem-file',
            'Content-Disposition' => "attachment; filename=\"$fileName\""
        ]);
    }
}
