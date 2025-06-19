<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Auth\Events\Registered;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\Rules;
use Illuminate\View\View;

class RegisteredUserController extends Controller
{
    /**
     * Display the registration view.
     */
    public function create(): View
    {
        return view('auth.register');
    }

    /**
     * Handle an incoming registration request.
     *
     * @throws \Illuminate\Validation\ValidationException
     */
    public function store(Request $request): RedirectResponse
    {
        $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'string', 'lowercase', 'email', 'max:255', 'unique:' . User::class],
            'password' => ['required', 'confirmed', Rules\Password::defaults()],
        ]);

        // ✅ Step 1: Create user (without keys yet)
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        // ✅ Step 2: Generate RSA key pair
        $keyPair = openssl_pkey_new(['private_key_bits' => 2048]);
        openssl_pkey_export($keyPair, $privateKey); // Export private key to string
        $publicKey = openssl_pkey_get_details($keyPair)['key']; // Extract public key

        // ✅ Step 3: Store public and private keys
        $user->public_key = $publicKey;
        $user->private_key = Crypt::encryptString($privateKey); // Store securely
        $user->save();

        // ✅ Step 4: Continue normal flow
        event(new Registered($user));
        Auth::login($user);

        return redirect(route('dashboard', absolute: false));
    }
}
