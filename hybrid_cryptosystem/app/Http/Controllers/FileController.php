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
    $recipients = \App\Models\User::where('id', '!=', auth()->id())->get();
    return view('profile.encrypt_all', compact('recipients'));
}

    public function showDecryptForm()
    {
        return view('decrypt');
    }

    public function showRSAEncryptForm() { return view('rsa_encrypt'); }
    public function showRSADecryptForm() { return view('rsa_decrypt'); }
    public function showHybridEncryptForm() { return view('hybrid_encrypt'); }
    public function showHybridDecryptForm() { return view('hybrid_decrypt'); }

    public function encryptAES(Request $request)
{
    $start = microtime(true); // Start timer immediately

    // ✅ Validate input
    $request->validate([
        'file' => 'required|file',
        'password' => 'required|string|min:4',
        'filename' => 'required|string'
    ]);

    $file = $request->file('file');
    $excludedExtensions = ['jpg', 'jpeg', 'png', 'exe', 'dll', 'bat'];
    $extension = strtolower($file->getClientOriginalExtension());

    // ❌ Block excluded file types
    if (in_array($extension, $excludedExtensions)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
    }

    $originalName = $file->getClientOriginalName();
    if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted. Please upload a different file.']);
    }

    $password = $request->input('password');
    $filename = $request->input('filename') . '.enc';
    $data = file_get_contents($file->getRealPath());

    // ✅ Generate salt, key, iv
    $salt = random_bytes(16);
    $key = hash_pbkdf2("sha256", $password, $salt, 100000, 32, true);
    $iv = random_bytes(12); // GCM recommended length
    $tag = '';

    // 🔒 Perform encryption
    $cipher = openssl_encrypt(
        $data,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($cipher === false) {
        return back()->withErrors(['file' => 'Encryption failed.']);
    }

    // ✅ Build encrypted file format
    $encrypted = 'AES' . $salt . $iv . $tag . $cipher;

    // 💾 Save file
    $path = storage_path("app/encrypted");
    if (!file_exists($path)) {
        mkdir($path, 0777, true);
    }
    file_put_contents("$path/$filename", $encrypted);

    // ⏱️ End timer and log
    $end = microtime(true);
    $duration = round($end - $start, 3);
    $memoryUsed = memory_get_peak_usage(true);

    \App\Models\EncryptionLog::create([
        'user_id' => Auth::id(),
        'file_name' => $filename,
        'algorithm' => 'AES',
        'file_size' => strlen($data),
        'duration' => $duration,
        'memory_used' => $memoryUsed,
    ]);

    // ✅ Flash session for download
    session()->flash('download_file', $filename);
    session()->flash('original_name', $filename);

    // ✅ Return redirect as response
    return redirect()->route('encrypt.form')->with([
    'success' => 'AES encryption successful!',
    'download_url' => route('download.encrypted', ['filename' => $filename]),
    ]);

}



    public function decryptAES(Request $request)
{
    $request->validate([
        'file' => 'required|file',
        'password' => 'required|string|min:4',
    ]);

    $start = microtime(true);
    $file = $request->file('file');
    $password = $request->input('password');
    $data = file_get_contents($file->getRealPath());

    if (substr($data, 0, 3) !== 'AES') {
        return back()->withErrors(['file' => 'Invalid file format.']);
    }

    $salt = substr($data, 3, 16);
    $iv = substr($data, 19, 12);
    $tag = substr($data, 31, 16);
    $cipher = substr($data, 47);

    $key = hash_pbkdf2("sha256", $password, $salt, 100000, 32, true);

    $decrypted = openssl_decrypt(
        $cipher,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($decrypted === false) {
        return back()->withErrors(['password' => 'Decryption failed: wrong password or tampered file.']);
    }

    $outputName = 'decrypted_aes_' . time() . '.txt';
    $decryptedPath = storage_path('app/decrypted');
    if (!file_exists($decryptedPath)) {
        mkdir($decryptedPath, 0777, true);
    }
    file_put_contents("$decryptedPath/$outputName", $decrypted);

    $memoryUsed = memory_get_peak_usage(true);

    \App\Models\EncryptionLog::create([
        'user_id' => auth()->id(),
        'file_name' => $file->getClientOriginalName(),
        'algorithm' => 'AES',
        'file_size' => $file->getSize(),
        'duration' => round(microtime(true) - $start, 5),
        'type' => 'DECRYPT',
        'memory_used' => $memoryUsed,
    ]);

    session()->flash('success', 'AES decryption successful!');
    session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
    session()->flash('download_name', $outputName);

    return redirect()->route('decrypt.form');

}



    public function encryptRSA(Request $request)
{
    $start = microtime(true); // ⏱️ Start timer immediately

    // ✅ Validate inputs
    $request->validate([
        'file' => 'required|file',
        'filename' => 'required|string',
        'password' => 'required|string|min:4',
        'recipient_id' => 'required|exists:users,id',
    ]);

    $file = $request->file('file');
    $originalName = $file->getClientOriginalName();

    // ❌ Prevent re-encryption
    if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted.']);
    }

    $data = file_get_contents($file->getRealPath());

    // ⚠️ RSA size limitation check (2048-bit key typical limit ~190 bytes)
    if (strlen($data) > 190) {
        return back()->withErrors(['file' => 'RSA can only encrypt small files (≤190 bytes).']);
    }

    $filename = $request->input('filename') . '.enc';
    $password = $request->input('password');
    $recipientId = $request->input('recipient_id');

    // 🔑 Get recipient public key from DB
    $recipient = \App\Models\User::findOrFail($recipientId);
    $recipientPublicKey = $recipient->public_key;

    if (!$recipientPublicKey) {
        return back()->withErrors(['recipient_id' => 'Recipient public key not found.']);
    }

    // 🔒 Perform RSA encryption
    if (!openssl_public_encrypt($data, $encryptedData, $recipientPublicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return back()->withErrors(['file' => 'RSA encryption failed.']);
    }

    // 🧐 Stress test (optional loop)
    for ($i = 0; $i < 20; $i++) {
        openssl_public_encrypt($data, $temp, $recipientPublicKey, OPENSSL_PKCS1_OAEP_PADDING);
    }

    // 🔑 Append SHA-256 hash of password for integrity
    $hash = hash('sha256', $password);
    $payload = 'RSA' . $encryptedData . $hash;

    // 💾 Save encrypted file
    $encPath = storage_path('app/encrypted');
    if (!file_exists($encPath)) {
        mkdir($encPath, 0777, true);
    }
    file_put_contents("$encPath/$filename", $payload);

    // 📝 Log encryption metadata
    \App\Models\EncryptionLog::create([
        'user_id' => auth()->id(),
        'file_name' => $filename,
        'algorithm' => 'RSA',
        'file_size' => strlen($data),
        'duration' => round(microtime(true) - $start, 5),
        'type' => 'ENCRYPT',
        'recipient_id' => $recipient->id,
        'memory_used' => memory_get_peak_usage(true),
    ]);

    // ✅ Flash session for download success
    session()->flash('download_file', $filename);
    session()->flash('success', 'RSA encryption successful!');

    // 🔙 Redirect back
    return redirect()->route('encrypt.form')->with([
    'success' => 'RSA encryption successful!',
    'download_url' => route('download.encrypted', ['filename' => $filename]),
    ]);
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
    $privateKeyFile = $request->file('private_key');
    $password = $request->input('password');

    $encData = file_get_contents($encFile->getRealPath());
    $privateKeyData = file_get_contents($privateKeyFile->getRealPath());

    if (substr($encData, 0, 3) !== 'RSA') {
        return back()->withErrors(['file' => 'Invalid RSA file format.']);
    }

    $payload = substr($encData, 3);
    $cipher = substr($payload, 0, -64);
    $storedHash = substr($payload, -64);
    $inputHash = hash('sha256', $password);

    if (!hash_equals($storedHash, $inputHash)) {
        return back()->withErrors(['password' => 'Incorrect password.']);
    }

    // Load private key (no passphrase needed here)
    $privateKey = openssl_pkey_get_private($privateKeyData);
    if (!$privateKey) {
        return back()->withErrors(['private_key' => 'Failed to load private key.']);
    }

    // Decrypt
    if (!openssl_private_decrypt($cipher, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return back()->withErrors(['file' => 'RSA decryption failed.']);
    }
    for ($i = 0; $i < 20; $i++) {
    openssl_private_decrypt($cipher, $temp, $privateKey, OPENSSL_PKCS1_OAEP_PADDING);
    }

    // Save decrypted file
    $outputName = 'decrypted_rsa_' . time() . '.txt';
    $decryptedPath = storage_path('app/decrypted');
    if (!file_exists($decryptedPath)) mkdir($decryptedPath, 0777, true);
    file_put_contents("$decryptedPath/$outputName", $decrypted);

    // Log
    \App\Models\EncryptionLog::create([
        'user_id' => auth()->id(),
        'file_name' => $encFile->getClientOriginalName(),
        'algorithm' => 'RSA',
        'file_size' => $encFile->getSize(),
        'duration' => round(microtime(true) - $start, 5),
        'type' => 'DECRYPT',
        'memory_used' => memory_get_peak_usage(true),
    ]);

    session()->flash('success', 'RSA decryption successful!');
    session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
    session()->flash('download_name', $outputName);
    return redirect()->route('decrypt.form')->with([
    'success' => 'RSA decryption successful!',
    'download_url' => route('download.decrypted', ['filename' => $outputName]),
    ]);

}



    public function encryptHybrid(Request $request)
{
    $start = microtime(true); // ⏱️ Start timer early

    // ✅ Validate inputs
    $request->validate([
        'file' => 'required|file',
        'filename' => 'required|string',
        'password' => 'required|string|min:4',
        'recipient_id' => 'required|exists:users,id',
    ]);

    $file = $request->file('file');
    $extension = $file->getClientOriginalExtension();
    $excludedExtensions = ['jpg', 'jpeg', 'png', 'exe', 'dll', 'bat'];

    // ❌ Disallow excluded file types
    if (in_array(strtolower($extension), $excludedExtensions)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
    }

    $originalName = $file->getClientOriginalName();

    // ❌ Prevent re-encryption
    if (str_ends_with($originalName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted.']);
    }

    // 📄 Gather inputs
    $filename = $request->input('filename') . '.enc';
    $password = $request->input('password');
    $recipientId = $request->input('recipient_id');
    $data = file_get_contents($file->getRealPath());

    // 🔑 Generate AES key and IV
    $aesKey = random_bytes(32); // AES-256 key
    $iv = random_bytes(16);     // CBC mode IV

    // 🔒 Encrypt file data with AES
    $cipher = openssl_encrypt($data, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);

    // 🔑 Fetch recipient public key
    $recipient = \App\Models\User::findOrFail($recipientId);
    $recipientPublicKey = $recipient->public_key;

    if (!$recipientPublicKey) {
        return back()->withErrors(['recipient_id' => 'Recipient public key not found.']);
    }

    // 🔐 Encrypt AES key with recipient public key
    if (!openssl_public_encrypt($aesKey, $encryptedAESKey, $recipientPublicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        return back()->withErrors(['file' => 'Failed to encrypt AES key with public key.']);
    }

    // 📝 Append SHA-256 hash of password for integrity verification
    $hash = hash('sha256', $password);

    // 📦 Build hybrid payload
    $hybridData = 'HYB'
                . pack('n', strlen($encryptedAESKey))
                . $encryptedAESKey
                . $iv
                . $cipher
                . $hash;

    // 💾 Save encrypted file
    $encPath = storage_path('app/encrypted');
    if (!file_exists($encPath)) {
        mkdir($encPath, 0777, true);
    }
    file_put_contents("$encPath/$filename", $hybridData);

    // 📊 Log encryption activity
    \App\Models\EncryptionLog::create([
        'user_id' => auth()->id(),
        'file_name' => $filename,
        'algorithm' => 'HYBRID',
        'file_size' => strlen($data),
        'duration' => round(microtime(true) - $start, 5),
        'type' => 'ENCRYPT',
        'recipient_id' => $recipient->id,
        'memory_used' => memory_get_peak_usage(true),
    ]);

    // ✅ Flash session for UI success
    session()->flash('download_file', $filename);
    session()->flash('success', 'Hybrid encryption successful!');
    return redirect()->route('encrypt.form')->with([
    'success' => 'Hybrid encryption successful!',
    'download_url' => route('download.encrypted', ['filename' => $filename]),
    ]);
}


    public function decryptHybrid(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'private_key' => 'required|file',
            'password' => 'required|string|min:4',
        ]);

        $start = microtime(true);

        $encData = file_get_contents($request->file('file')->getRealPath());
        $privateKeyData = file_get_contents($request->file('private_key')->getRealPath());
        $password = $request->input('password');

        if (substr($encData, 0, 3) !== 'HYB') {
            return back()->withErrors(['file' => 'Invalid HYBRID file format.']);
        }

        $keyLen = unpack('n', substr($encData, 3, 2))[1];
        $encryptedKey = substr($encData, 5, $keyLen);
        $iv = substr($encData, 5 + $keyLen, 16);
        $payloadWithHash = substr($encData, 5 + $keyLen + 16);
        $storedHash = substr($payloadWithHash, -64);
        $cipher = substr($payloadWithHash, 0, -64);
        $inputHash = hash('sha256', $password);

        if (!hash_equals($storedHash, $inputHash)) {
            return back()->withErrors(['password' => 'Incorrect password.']);
        }

        $privateKey = openssl_pkey_get_private($privateKeyData, $password);
        if (!$privateKey) {
            return back()->withErrors(['private_key' => 'Failed to load private key.']);
        }

        if (!openssl_private_decrypt($encryptedKey, $aesKey, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return back()->withErrors(['file' => 'Failed to decrypt AES key.']);
        }

        $decrypted = openssl_decrypt($cipher, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            return back()->withErrors(['file' => 'Final AES decryption failed.']);
        }

        $outputName = 'decrypted_hybrid_' . time() . '.txt';
        $path = storage_path('app/decrypted');
        if (!file_exists($path)) mkdir($path, 0777, true);
        file_put_contents("$path/$outputName", $decrypted);


        $memoryUsed = memory_get_peak_usage(true);

        EncryptionLog::create([
            'user_id' => auth()->id(),
            'file_name' => $request->file('file')->getClientOriginalName(),
            'algorithm' => 'HYBRID',
            'file_size' => $request->file('file')->getSize(),
            'duration' => round(microtime(true) - $start, 5),
            'type' => 'DECRYPT',
            'memory_used' => $memoryUsed,

        ]);

        session()->flash('success', 'Hybrid decryption successful!');
        session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
        session()->flash('download_name', $outputName);
        return redirect()->route('decrypt.form')->with([
        'success' => 'Hybrid decryption successful!',
        'download_url' => route('download.decrypted', ['filename' => $outputName]),
            ]);

    }

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
    $start = microtime(true); // Start timer

    $algorithm = $request->input('algorithm');
    $response = null;

    if ($algorithm == 'AES') {
        $response = $this->encryptAES($request);
    } elseif ($algorithm == 'RSA') {
        $response = $this->encryptRSA($request);
    } elseif ($algorithm == 'HYBRID') {
        $response = $this->encryptHybrid($request);
    } else {
        return back()->withErrors(['algorithm' => 'Invalid encryption method selected.']);
    }

    return $response;
}

    public function autoDecrypt(Request $request)
{
    $algorithm = $request->input('algorithm');

    if ($algorithm == 'AES') {
        return $this->decryptAES($request);
    } elseif ($algorithm == 'RSA') {
        return $this->decryptRSA($request);
    } elseif ($algorithm == 'HYBRID') {
        return $this->decryptHybrid($request);
    } else {
        return back()->withErrors(['algorithm' => 'Invalid decryption method selected.']);
    }

}



    public function downloadPrivateKey($filename)
    {
        $path = storage_path("app/keys/$filename");
        if (!file_exists($path)) abort(404);
        return response()->download($path);
    }

}
