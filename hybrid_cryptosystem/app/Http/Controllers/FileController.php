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

        $extension = strtolower($file->getClientOriginalExtension());

        $blockedExtensions = ['jpg', 'jpeg', 'png', 'exe', 'dll', 'bat'];
        if (in_array($extension, $blockedExtensions)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
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
        'password' => 'required|string|min:4',
    ]);

    $file = $request->file('file');

    $originalName = $file->getClientOriginalName();

    if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted. Please upload a different file.']);
    }

    $extension = strtolower($file->getClientOriginalExtension());
    $blockedExtensions = ['jpg', 'jpeg', 'png', 'exe', 'dll', 'bat'];
    if (in_array($extension, $blockedExtensions)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
    }

    $filename = $request->input('filename') ?: $originalName;
    $password = $request->input('password');
    $data = file_get_contents($file->getRealPath());

    if (strlen($data) > 190) {
        return back()->withErrors(['file' => 'RSA can only encrypt small files. Use Hybrid for large files.']);
    }

    $start = microtime(true);

    $keyConfig = [
        "private_key_type" => OPENSSL_KEYTYPE_RSA,
        "private_key_bits" => 2048,
    ];
    $res = openssl_pkey_new($keyConfig);
    if (!$res) {
        $msg = "Failed to generate RSA key. OpenSSL error: " . implode(", ", array_filter([openssl_error_string()]));
        return back()->withErrors(['file' => $msg]);
    }

    openssl_pkey_export($res, $privateKeyPEM);
    $pubKeyDetails = openssl_pkey_get_details($res);
    $publicKeyPEM = $pubKeyDetails["key"];

    openssl_public_encrypt($data, $encryptedData, $publicKeyPEM, OPENSSL_PKCS1_OAEP_PADDING);

    // ✅ Add password hash to the end of the encrypted file
    $hashedPassword = $password ? hash('sha256', $password) : str_repeat('0', 64);
    $output = 'RSA' . $encryptedData . $hashedPassword;

    $encFilename = pathinfo($filename, PATHINFO_FILENAME) . '.enc';
    $keyFilename = pathinfo($filename, PATHINFO_FILENAME) . '_private.pem';

    $encPath = storage_path("app/encrypted");
    $keyPath = storage_path("app/keys");

    if (!file_exists($encPath)) mkdir($encPath, 0777, true);
    if (!file_exists($keyPath)) mkdir($keyPath, 0777, true);

    file_put_contents("$encPath/$encFilename", $output);
    file_put_contents("$keyPath/$keyFilename", $privateKeyPEM);

    $end = microtime(true);

    EncryptionLog::create([
        'user_id' => Auth::id(),
        'file_name' => $filename,
        'algorithm' => 'RSA',
        'file_size' => strlen($data),
        'duration' => round($end - $start, 3),
    ]);

    session()->flash('download_file', $encFilename);
    session()->flash('original_name', $encFilename);
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

    $extension = strtolower($file->getClientOriginalExtension());

        $blockedExtensions = ['jpg', 'jpeg', 'png', 'exe', 'dll', 'bat'];
        if (in_array($extension, $blockedExtensions)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
        }


    $filename = $request->input('filename') . '.enc';
    $password = $request->input('password');
    $passwordHash = hash('sha256', $password);
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
    $hybridData = 'HYB' . pack('n', strlen($encryptedAESKey)) . $encryptedAESKey . $iv . $cipher . $passwordHash;

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
    session()->flash('success', 'Hybrid encryption successful!');
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

    $encFile = $request->file('file');
    $keyFile = $request->file('private_key');
    $password = $request->input('password');

    $encData = file_get_contents($encFile->getRealPath());
    $privateKeyData = file_get_contents($keyFile->getRealPath());

    if (!str_starts_with($encData, 'RSA')) {
        return back()->withErrors(['file' => 'Invalid file format. File must start with RSA.']);
    }

    $payload     = substr($encData, 3);
    $cipherHex   = substr($payload, 0, -64);
    $storedHash  = substr($payload, -64);

    $enteredHash = hash('sha256', $password);
    if ($enteredHash !== $storedHash) {
        return back()->withErrors(['password' => 'Incorrect password. Decryption aborted.']);
    }

    // 🔐 Load unencrypted private key
    $privateKey = openssl_pkey_get_private($privateKeyData); // no password param
    if (!$privateKey) {
        return back()->withErrors(['private_key' => 'Failed to load private key. Key may be corrupted or encrypted.']);
    }

    $decrypted = '';
    $keyDetails = openssl_pkey_get_details($privateKey);
    $chunkSize = $keyDetails['bits'] / 8;

    $cipher = $cipherHex;
    foreach (str_split($cipher, $chunkSize) as $chunk) {
        if (!openssl_private_decrypt($chunk, $partial, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return back()->withErrors(['file' => 'RSA decryption failed. Possibly wrong key or corrupted data.']);
        }
        $decrypted .= $partial;
    }

    openssl_free_key($privateKey);

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

    $start = microtime(true);

    $encFile = $request->file('file');
    $keyFile = $request->file('private_key');
    $password = $request->input('password');

    $encData = file_get_contents($encFile->getRealPath());
    $privateKeyData = file_get_contents($keyFile->getRealPath());

    if (!str_starts_with($encData, 'HYB')) {
        return back()->withErrors(['file' => 'Invalid file format. File must start with HYB.']);
    }

    $keyLen = unpack('n', substr($encData, 3, 2))[1];
    $encryptedAESKey = substr($encData, 5, $keyLen);
    $iv = substr($encData, 5 + $keyLen, 16);
    $cipherAndHash = substr($encData, 5 + $keyLen + 16);
    $storedHash = substr($cipherAndHash, -64);
    $cipherText = substr($cipherAndHash, 0, -64);

    $enteredHash = hash('sha256', $password);
    if ($enteredHash !== $storedHash) {
        return back()->withErrors(['password' => 'Incorrect password. Decryption aborted.']);
    }

    // 🔐 Load unencrypted private key
    $privateKey = openssl_pkey_get_private($privateKeyData); // no password param
    if (!$privateKey) {
        return back()->withErrors(['private_key' => 'Failed to load private key. Key may be corrupted or encrypted.']);
    }

    $aesKeyRaw = '';
    if (!openssl_private_decrypt($encryptedAESKey, $aesKeyRaw, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return back()->withErrors(['file' => 'Failed to decrypt AES key. Possibly incorrect private key.']);
    }

    if (strlen($aesKeyRaw) !== 32) {
        return back()->withErrors(['file' => 'Decrypted AES key is invalid length. Expected 32 bytes.']);
    }

    $decrypted = openssl_decrypt($cipherText, 'aes-256-cbc', $aesKeyRaw, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        return back()->withErrors(['file' => 'Failed to decrypt the final ciphertext.']);
    }

    $outputName = 'decrypted_hybrid_' . time() . '.txt';
    $decryptedPath = storage_path('app/decrypted');
    if (!file_exists($decryptedPath)) mkdir($decryptedPath, 0777, true);
    file_put_contents("$decryptedPath/$outputName", $decrypted);

    \App\Models\EncryptionLog::create([
        'user_id'   => auth()->id(),
        'file_name' => $encFile->getClientOriginalName(),
        'algorithm' => 'HYBRID',
        'file_size' => $encFile->getSize(),
        'duration'  => round(microtime(true) - $start, 5),
        'type'      => 'DECRYPT',
    ]);

    session()->flash('success', 'Hybrid decryption successful!');
    session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
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
