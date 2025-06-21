<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Auth;
use App\Models\EncryptionLog;
use App\Models\User;


class FileController extends Controller
{
    public function showEncryptForm()
    {
        $users = \App\Models\User::where('id', '!=', auth()->id())->get(); // exclude self
        return view('profile.encrypt_all', compact('users'));
    }
    public function showDecryptForm()
    {
        return view('decrypt');
    }

    public function encryptAES(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'password' => 'required|string|min:4',
            'filename' => 'required|string'
        ]);

        $file = $request->file('file');

        $originalName = $request->file('file')->getClientOriginalName();

        if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted. Please upload a different file.']);
        }


        $password = $request->input('password');
        $filename = $request->input('filename') . '.enc';
        $data = file_get_contents($file->getRealPath());

        $start = microtime(true);

        $salt = random_bytes(16);
        $key = hash_pbkdf2("sha256", $password, $salt, 100000, 32, true);
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $salt . $iv . $cipher, $key, true);
        $encrypted = 'AES' . $salt . $iv . $cipher . $hmac;

        $path = storage_path("app/encrypted");
        if (!file_exists($path)) {
            mkdir($path, 0777, true);
        }
        file_put_contents("$path/$filename", $encrypted);

        $end = microtime(true);

        EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'AES',
            'file_size' => strlen($data),
            'duration' => round($end - $start, 3),
        ]);

        session()->flash('download_file', $filename);
        session()->flash('original_name', $filename);
        session()->flash('success', 'AES encryption successful!');
        return redirect()->back();
    }

    public function encryptRSA(Request $request)
{
    $request->validate([
        'file' => 'required|file',
        'filename' => 'nullable|string',
        'password' => 'nullable|string|min:4',
        'recipient_id' => 'required|exists:users,id',
    ]);

    $file = $request->file('file');
    $originalName = $file->getClientOriginalName();

    // ✅ Prevent double encryption
    if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted. Please upload a different file.']);
    }

    // ✅ Get recipient
    $recipient = \App\Models\User::find($request->recipient_id);
    if (!$recipient || empty($recipient->public_key)) {
        return back()->withErrors(['recipient' => 'Recipient public key not found.']);
    }

    // ✅ Read content to encrypt
    $data = file_get_contents($file->getRealPath());
    $filename = ($request->input('filename') ?: pathinfo($originalName, PATHINFO_FILENAME)) . '.enc';

    // ✅ Encrypt with public key using OAEP padding
    $publicKey = openssl_pkey_get_public($recipient->public_key);
    if (!$publicKey) {
        return back()->withErrors(['recipient' => 'Invalid public key.']);
    }

    if (!openssl_public_encrypt($data, $encrypted, $publicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        $error = openssl_error_string();
        return back()->withErrors(['file' => "RSA encryption failed. $error"]);
    }

    // ✅ Prefix and save
    $encryptedPayload = 'RSA' . $encrypted;

    $path = storage_path("app/encrypted");
    if (!file_exists($path)) {
        mkdir($path, 0777, true);
    }

    file_put_contents("$path/$filename", $encryptedPayload);

    // ✅ Log
    EncryptionLog::create([
        'user_id' => Auth::id(),
        'file_name' => $filename,
        'algorithm' => 'RSA',
        'file_size' => strlen($data),
        'duration' => round(microtime(true) - LARAVEL_START, 3),
        'type' => 'ENCRYPT',
        'recipient_id' => $recipient->id,
    ]);

    session()->flash('download_file', $filename);
    session()->flash('original_name', $filename);
    session()->flash('success', 'RSA encryption successful!');
    return redirect()->back();
}

    public function encryptHybrid(Request $request)
{
    $request->validate([
        'file' => 'required|file',
        'filename' => 'required|string',
        'password' => 'required|string|min:4',
        'recipient_id' => 'required|exists:users,id',
    ]);

    $file = $request->file('file');

        $originalName = $request->file('file')->getClientOriginalName();

    if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted. Please upload a different file.']);
    }


    $filename = $request->input('filename') . '.enc';
    $password = $request->input('password');
    $recipientId = $request->input('recipient_id');
    $data = file_get_contents($file->getRealPath());

    $start = microtime(true);

    // Step 1: Generate AES key + IV
    $aesKey = random_bytes(32); // 256-bit AES key
    $iv = random_bytes(16);     // 128-bit IV

    // Step 2: Encrypt file with AES
    $cipher = openssl_encrypt($data, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);

    // Step 3: Get recipient's public key from DB
    $recipient = User::findOrFail($recipientId);
    $recipientPublicKey = $recipient->public_key;

    if (!$recipientPublicKey) {
        return back()->withErrors(['recipient_id' => 'Recipient does not have a public key.']);
    }

    // Step 4: Encrypt AES key with recipient's public key
    if (!openssl_public_encrypt($aesKey, $encryptedAESKey, $recipientPublicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return back()->withErrors(['file' => 'Failed to encrypt AES key with recipient public key.']);
    }

    // Step 5: Combine data into Hybrid file format
    $hybridData = 'HYB' . pack('n', strlen($encryptedAESKey)) . $encryptedAESKey . $iv . $cipher;

    // Step 6: Store encrypted file
    $encPath = storage_path("app/encrypted");
    if (!file_exists($encPath)) mkdir($encPath, 0777, true);
    file_put_contents("$encPath/$filename", $hybridData);

    // Step 7: Log it
    EncryptionLog::create([
        'user_id' => Auth::id(),
        'file_name' => $filename,
        'algorithm' => 'HYBRID',
        'file_size' => strlen($data),
        'duration' => round(microtime(true) - $start, 3),
    ]);

    // Step 8: Return success
    session()->flash('success', 'Hybrid encryption successful! Download will begin now.');
    session()->flash('download_file', $filename);
    session()->flash('original_name', $filename);

    return redirect()->back();
}

    public function decryptAES(Request $request)
{
    $request->validate([
        'file' => 'required|file',
        'password' => 'required|string|min:4',
    ]);

    $start = microtime(true); // Start timing

    $file = $request->file('file');
    $password = $request->input('password');
    $data = file_get_contents($file->getRealPath());

    if (substr($data, 0, 3) !== 'AES') {
        return back()->withErrors(['file' => 'Invalid file format.']);
    }

    $salt = substr($data, 3, 16);
    $iv = substr($data, 19, 16);
    $hmac = substr($data, -32);
    $cipher = substr($data, 35, -32);

    $key = hash_pbkdf2("sha256", $password, $salt, 100000, 32, true);
    $calculatedHmac = hash_hmac('sha256', $salt . $iv . $cipher, $key, true);

    if (!hash_equals($hmac, $calculatedHmac)) {
        return back()->withErrors(['password' => 'Decryption failed: wrong password or tampered file.']);
    }

    $decrypted = openssl_decrypt($cipher, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);

    if ($decrypted === false) {
        return back()->withErrors(['file' => 'Decryption failed due to an internal error.']);
    }

    $outputName = 'decrypted_aes_' . time() . '.txt';
    $decryptedPath = storage_path('app/decrypted');
    if (!file_exists($decryptedPath)) {
        mkdir($decryptedPath, 0777, true);
    }
    file_put_contents("$decryptedPath/$outputName", $decrypted);

    // ✅ Log the decryption
    \App\Models\EncryptionLog::create([
        'user_id'   => auth()->id(),
        'file_name' => $file->getClientOriginalName(),
        'algorithm' => 'AES',
        'file_size' => $file->getSize(),
        'duration'  => round(microtime(true) - $start, 5),
        'type'      => 'DECRYPT',
    ]);

    // ✅ SweetAlert download
    session()->flash('success', 'AES decryption successful!');
    session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
    session()->flash('download_name', $outputName);

    return redirect()->route('decrypt.form');
}

    public function decryptRSA(Request $request)
{
    $request->validate([
        'file' => 'required|file',
        'private_key' => 'required|file',
        'password' => 'required|string|min:4',
    ]);

    $start = microtime(true);

    // ✅ Validate uploaded files
    $encFile = $request->file('file');
    $keyFile = $request->file('private_key');
    $password = $request->input('password');

    if (!$encFile->isValid() || !$keyFile->isValid()) {
        return back()->withErrors(['file' => 'File upload failed.']);
    }

    // ✅ Load encrypted content
    $encData = file_get_contents($encFile->getRealPath());
    if (substr($encData, 0, 3) !== 'RSA') {
        return back()->withErrors(['file' => 'Invalid file format.']);
    }

    $cipher = substr($encData, 3);

    // ✅ Read private key file content
    $rawKey = file_get_contents($keyFile->getRealPath());
    if (empty($rawKey)) {
        return back()->withErrors(['private_key' => 'Uploaded key file is empty.']);
    }

    // ✅ Fix escaped PEM (if uploaded with \n)
    if (str_contains($rawKey, '\\n')) {
        $privateKeyData = json_decode('"' . trim($rawKey) . '"');
    } else {
        $privateKeyData = $rawKey;
    }

    // ✅ Load private key
    $privateKey = openssl_pkey_get_private($privateKeyData, $password);
    if (!$privateKey) {
        $error = openssl_error_string();
        return back()->withErrors(['private_key' => "Failed to load private key. $error"]);
    }

    // ✅ Decrypt
    if (!openssl_private_decrypt($cipher, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        $error = openssl_error_string();
        return back()->withErrors(['file' => "RSA decryption failed. $error"]);
    }

    // ✅ Save and log
    $outputName = 'decrypted_rsa_' . time() . '.txt';
    $decryptedPath = storage_path('app/decrypted');
    if (!file_exists($decryptedPath)) mkdir($decryptedPath, 0777, true);
    file_put_contents("$decryptedPath/$outputName", $decrypted);

    \App\Models\EncryptionLog::create([
        'user_id'   => auth()->id(),
        'file_name' => $encFile->getClientOriginalName(),
        'algorithm' => 'RSA',
        'file_size' => $encFile->getSize(),
        'duration'  => round(microtime(true) - $start, 5),
        'type'      => 'DECRYPT',
    ]);

    session()->flash('success', 'RSA decryption successful!');
    session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
    session()->flash('download_name', $outputName);

    return redirect()->route('decrypt.form');
}



    public function decryptHybrid(Request $request)
{
    $request->validate([
        'file' => 'required|file',
        'private_key' => 'required|file',
        'password' => 'required|string|min:4',
    ]);

    $start = microtime(true); // ✅ Track decryption time

    $encFile = $request->file('file');
    $keyFile = $request->file('private_key');
    $password = $request->input('password');
    $encData = file_get_contents($encFile->getRealPath());
    $privateKeyData = file_get_contents($keyFile->getRealPath());
    $privateKeyData = str_replace("\\n", "\n", $privateKeyData);


    if (substr($encData, 0, 3) !== 'HYB') {
        return back()->withErrors(['file' => 'Invalid file format. File must start with HYB.']);
    }

    $keyLen = unpack('n', substr($encData, 3, 2))[1];
    $encryptedAESKey = substr($encData, 5, $keyLen);
    $iv = substr($encData, 5 + $keyLen, 16);
    $cipherText = substr($encData, 5 + $keyLen + 16);

    $privateKey = openssl_pkey_get_private($privateKeyData, $password);
    if (!$privateKey) {
        return back()->withErrors(['private_key' => 'Invalid private key or password.']);
    }

    if (!openssl_private_decrypt($encryptedAESKey, $aesKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return back()->withErrors(['file' => 'Failed to decrypt AES key.']);
    }

    $decrypted = openssl_decrypt($cipherText, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        return back()->withErrors(['file' => 'Failed to decrypt the final ciphertext.']);
    }

    $outputName = 'decrypted_hybrid_' . time() . '.txt';
    $downloadUrl = route('download.decrypted', ['filename' => $outputName]);

    $decryptedPath = storage_path('app/decrypted');
    if (!file_exists($decryptedPath)) mkdir($decryptedPath, 0777, true);
    file_put_contents("$decryptedPath/$outputName", $decrypted);

    // ✅ Log hybrid decryption
    \App\Models\EncryptionLog::create([
        'user_id'   => auth()->id(),
        'file_name' => $encFile->getClientOriginalName(),
        'algorithm' => 'HYBRID',
        'file_size' => $encFile->getSize(),
        'duration'  => round(microtime(true) - $start, 5),
        'type'      => 'DECRYPT',
    ]);

    session()->flash('success', 'Hybrid decryption successful!');
    session()->flash('download_url', $downloadUrl);
    session()->flash('download_name', $outputName);

    return redirect()->route('decrypt.form');
}

    public function showRSAEncryptForm() { return view('rsa_encrypt'); }
    public function showRSADecryptForm() { return view('rsa_decrypt'); }
    public function showHybridEncryptForm() { return view('hybrid_encrypt'); }
    public function showHybridDecryptForm() { return view('hybrid_decrypt'); }

    public function showHistory()
{
    $userId = Auth::id();

    $logs = \App\Models\EncryptionLog::where('user_id', $userId)
        ->orWhere('recipient_id', $userId)
        ->latest()
        ->get();

    $encryptionLogs = $logs->where('type', 'ENCRYPT')->values();
    $decryptionLogs = $logs->where('type', 'DECRYPT')->values();

    return view('history', compact('encryptionLogs', 'decryptionLogs'));
}



public function receivedHistory()
{
    $logs = \App\Models\EncryptionLog::with('user')
        ->where('recipient_id', Auth::id())
        ->latest()
        ->get();

    return view('received_history', compact('logs'));
}

    public function autoEncrypt(Request $request)
{
    $method = $request->input('method');
    $start = microtime(true); // Start timer
    $response = null;

    if ($method === 'AES') {
        $response = $this->encryptAES($request);
    } elseif ($method === 'RSA') {
        $response = $this->encryptRSA($request);
    } elseif ($method === 'HYBRID') {
        $response = $this->encryptHybrid($request);
    } else {
        return back()->withErrors(['method' => 'Invalid encryption method selected.']);
    }

    // Log only if encryption worked
    if ($response instanceof \Illuminate\Http\Response && $request->file('file')) {
        \App\Models\EncryptionLog::create([
            'user_id'   => auth()->id(),
            'filename'  => $request->file('file')->getClientOriginalName(),
            'algorithm' => strtoupper($method),
            'size'      => $request->file('file')->getSize(),
            'time'      => round(microtime(true) - $start, 5),
            'created_at' => now(),
        ]);
    }

    return $response;
}

    public function autoDecrypt(Request $request)
    {
        $mode = $request->input('mode');

        if ($mode === 'AES') {
            return $this->decryptAES($request);
        } elseif ($mode === 'RSA') {
            return $this->decryptRSA($request);
        } elseif ($mode === 'HYBRID') {
            return $this->decryptHybrid($request);
        }

        return back()->withErrors(['mode' => 'Invalid decryption mode selected.']);
    }

    public function downloadPrivateKey($filename)
    {
        $path = storage_path("app/keys/$filename");
        if (!file_exists($path)) abort(404);
        return response()->download($path);
    }
}
