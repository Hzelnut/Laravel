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
            return back()->withErrors(['file' => 'This file is already encrypted.']);
        }

        $filename = ($request->input('filename') ?: pathinfo($originalName, PATHINFO_FILENAME)) . '.enc';
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

        openssl_pkey_export($res, $privateKeyPEM, $password, [
            'encrypt_key' => true,
            'cipher' => 'aes-256-cbc'
        ]);

        $publicKeyPEM = openssl_pkey_get_details($res)['key'];

        if (!openssl_public_encrypt($data, $encryptedData, $publicKeyPEM, OPENSSL_PKCS1_OAEP_PADDING)) {
            return back()->withErrors(['file' => 'RSA encryption failed.']);
        }

        $hash = hash('sha256', $password);
        $finalPayload = 'RSA' . $encryptedData . $hash;

        $encPath = storage_path("app/encrypted");
        $keyPath = storage_path("app/keys");
        if (!file_exists($encPath)) mkdir($encPath, 0777, true);
        if (!file_exists($keyPath)) mkdir($keyPath, 0777, true);

        file_put_contents("$encPath/$filename", $finalPayload);
        file_put_contents("$keyPath/" . pathinfo($filename, PATHINFO_FILENAME) . "_private.pem", $privateKeyPEM);

        EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'RSA',
            'file_size' => strlen($data),
            'duration' => round(microtime(true) - $start, 5),
            'type' => 'ENCRYPT',
        ]);

        session()->flash('download_file', $filename);
        session()->flash('success', 'RSA encryption successful!');
        return redirect()->back();
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

        // ✅ Validate file header
        if (substr($encData, 0, 3) !== 'RSA') {
            return back()->withErrors(['file' => 'Invalid file format.']);
        }

        // ✅ Extract data
        $payload = substr($encData, 3);
        $cipher = substr($payload, 0, -64);
        $storedHash = substr($payload, -64);
        $inputHash = hash('sha256', $password);

        // ✅ Compare hashes to verify password
        if (!hash_equals($storedHash, $inputHash)) {
            return back()->withErrors(['password' => 'Incorrect password.']);
        }

        // ✅ Load private key (supports encrypted PEM)
        $privateKey = openssl_pkey_get_private($privateKeyData, $password);
        if (!$privateKey) {
            return back()->withErrors(['private_key' => 'Failed to load private key. Make sure the password is correct.']);
        }

        // ✅ Decrypt RSA
        if (!openssl_private_decrypt($cipher, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            $error = openssl_error_string();
            return back()->withErrors(['file' => "RSA decryption failed. $error"]);
        }

        // ✅ Save decrypted content
        $outputName = 'decrypted_rsa_' . time() . '.txt';
        $decryptedPath = storage_path('app/decrypted');
        if (!file_exists($decryptedPath)) mkdir($decryptedPath, 0777, true);
        file_put_contents("$decryptedPath/$outputName", $decrypted);

        // ✅ Log decryption
        \App\Models\EncryptionLog::create([
            'user_id' => auth()->id(),
            'file_name' => $encFile->getClientOriginalName(),
            'algorithm' => 'RSA',
            'file_size' => $encFile->getSize(),
            'duration' => round(microtime(true) - $start, 5),
            'type' => 'DECRYPT',
        ]);

        // ✅ Success flash & download link
        session()->flash('success', 'RSA decryption successful!');
        session()->flash('download_url', route('download.decrypted', ['filename' => $outputName]));
        session()->flash('download_name', $outputName);
        return redirect()->route('decrypt.form');
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
        $originalName = $file->getClientOriginalName();

        if (str_ends_with($originalName, '.enc')) {
            return back()->withErrors(['file' => 'This file is already encrypted.']);
        }

        $filename = $request->input('filename') . '.enc';
        $password = $request->input('password');
        $recipientId = $request->input('recipient_id');
        $data = file_get_contents($file->getRealPath());

        $start = microtime(true);

        // Generate AES key and IV
        $aesKey = random_bytes(32); // AES-256
        $iv = random_bytes(16);     // CBC IV

        // Encrypt the file content with AES
        $cipher = openssl_encrypt($data, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);

        // Fetch recipient public key
        $recipient = \App\Models\User::findOrFail($recipientId);
        $recipientPublicKey = $recipient->public_key;

        if (!$recipientPublicKey) {
            return back()->withErrors(['recipient_id' => 'Recipient public key not found.']);
        }

        // Encrypt the AES key with recipient's public key
        if (!openssl_public_encrypt($aesKey, $encryptedAESKey, $recipientPublicKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return back()->withErrors(['file' => 'Failed to encrypt AES key with public key.']);
        }

        // Final payload format
        $hash = hash('sha256', $password); // Used for decryption check
        $hybridData = 'HYB' . pack('n', strlen($encryptedAESKey)) . $encryptedAESKey . $iv . $cipher . $hash;

        $encPath = storage_path("app/encrypted");
        if (!file_exists($encPath)) mkdir($encPath, 0777, true);
        file_put_contents("$encPath/$filename", $hybridData);

        // Log encryption
        \App\Models\EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'HYBRID',
            'file_size' => strlen($data),
            'duration' => round(microtime(true) - $start, 5),
            'type' => 'ENCRYPT',
            'recipient_id' => $recipient->id,
        ]);

        session()->flash('download_file', $filename);
        session()->flash('success', 'Hybrid encryption successful!');
        return redirect()->back();
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

        EncryptionLog::create([
            'user_id' => auth()->id(),
            'file_name' => $request->file('file')->getClientOriginalName(),
            'algorithm' => 'HYBRID',
            'file_size' => $request->file('file')->getSize(),
            'duration' => round(microtime(true) - $start, 5),
            'type' => 'DECRYPT',
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
