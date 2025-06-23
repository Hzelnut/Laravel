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
        'file'     => 'required|file',
        'password' => 'required|string|min:4',
        'filename' => 'required|string'
    ]);

    $file = $request->file('file');
    $excluded = ['jpg','jpeg','png','exe','dll','bat'];
    $ext       = strtolower($file->getClientOriginalExtension());
    $origName  = $file->getClientOriginalName();

    if (in_array($ext, $excluded)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
    }
    if (str_ends_with($origName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted.']);
    }

    // Prepare paths & names
    $password  = $request->input('password');
    $outName   = $request->input('filename') . '.enc';
    $encDir    = storage_path('app/encrypted');
    if (! file_exists($encDir)) {
        mkdir($encDir, 0777, true);
    }
    $inPath    = $file->getRealPath();
    $outPath   = "$encDir/$outName";

    // --- START TIMER & MEMORY PROFILING ---
    $startTime = microtime(true);
    $startMem  = memory_get_usage();

    // Derive key + salt + iv
    $salt = random_bytes(16);
    $key  = hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
    $iv   = random_bytes(16);

    // Open streams
    $in  = fopen($inPath,  'rb');
    $out = fopen($outPath, 'wb');

    // Write header: tag + salt + iv
    fwrite($out, 'AES');
    fwrite($out, $salt);
    fwrite($out, $iv);

    // HMAC context (over salt|iv|cipher)
    $hmac = hash_init('sha256', HASH_HMAC, $key);
    hash_update($hmac, $salt . $iv);

    // Stream-encrypt in 1 MB chunks
    $chunkSize = 1024 * 1024;
    while (! feof($in)) {
        $plain  = fread($in, $chunkSize);
        $cipher = openssl_encrypt(
            $plain,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        fwrite($out, $cipher);
        hash_update($hmac, $cipher);

        // carry last block as next IV (CBC chaining)
        $iv = substr($cipher, -16);
    }

    // Finalize HMAC and append
    $tag = hash_final($hmac, true);
    fwrite($out, $tag);

    // Close streams
    fclose($in);
    fclose($out);

    // --- STOP TIMER & MEMORY ---
    $duration = round(microtime(true) - $startTime, 3);
    $memUsed  = memory_get_usage() - $startMem;

    // Log it
    \App\Models\EncryptionLog::create([
        'user_id'    => Auth::id(),
        'file_name'  => $outName,
        'algorithm'  => 'AES',
        'file_size'  => $file->getSize(),
        'duration'   => $duration,
        'memory_used'=> $memUsed,
    ]);

    // Flash download info
    session()->flash('download_file',   $outName);
    session()->flash('original_name',   $outName);
    session()->flash('success',         'AES encryption successful!');

    return redirect()->back();
}


    public function encryptRSA(Request $request)
{
    // 1) Validation
    $request->validate([
        'file'     => 'required|file',
        'filename' => 'nullable|string',
        'password' => 'required|string|min:4',
    ]);

    // 2) Exclude dangerous or image files
    $file      = $request->file('file');
    $excluded  = ['jpg','jpeg','png','exe','dll','bat'];
    $ext       = strtolower($file->getClientOriginalExtension());
    $origName  = $file->getClientOriginalName();

    if (in_array($ext, $excluded)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
    }
    if (str_ends_with($origName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted.']);
    }

    // 3) Prepare names & paths
    $password = $request->input('password');
    $outName  = ($request->input('filename') ?: pathinfo($origName, PATHINFO_FILENAME)) . '.enc';

    $encDir = storage_path('app/encrypted');
    $keyDir = storage_path('app/keys');
    if (! file_exists($encDir)) mkdir($encDir, 0777, true);
    if (! file_exists($keyDir)) mkdir($keyDir, 0777, true);

    $inPath  = $file->getRealPath();
    $outPath = "$encDir/$outName";

    // 4) Read data (RSA is small payload only)
    $data = file_get_contents($inPath);
    if (strlen($data) > 190) {
        return back()->withErrors(['file' => 'RSA can only encrypt small files. Use Hybrid for large files.']);
    }

    // 5) Start profiling
    $startTime = microtime(true);
    $startMem  = memory_get_usage();

    // 6) Generate RSA key pair
    $keyConfig = [
        'private_key_type' => OPENSSL_KEYTYPE_RSA,
        'private_key_bits' => 2048,
    ];
    $res = openssl_pkey_new($keyConfig);

    // 7) Export private key (password-protected)
    openssl_pkey_export($res, $privateKeyPEM, $password);

    // 8) Grab public key
    $publicKeyPEM = openssl_pkey_get_details($res)['key'];

    // 9) Encrypt data with OAEP padding
    openssl_public_encrypt(
        $data,
        $encryptedData,
        $publicKeyPEM,
        OPENSSL_PKCS1_OAEP_PADDING
    );

    // 10) Append SHA-256(password) for later verification
    $hash = hash('sha256', $password);
    $payload = 'RSA' . $encryptedData . $hash;

    // 11) Write files
    file_put_contents($outPath, $payload);
    file_put_contents(
        "$keyDir/" . pathinfo($outName, PATHINFO_FILENAME) . "_private.pem",
        $privateKeyPEM
    );

    // 12) Stop profiling
    $duration = round(microtime(true) - $startTime, 5);
    $memUsed  = memory_get_usage() - $startMem;

    // 13) Log
    \App\Models\EncryptionLog::create([
        'user_id'     => Auth::id(),
        'file_name'   => $outName,
        'algorithm'   => 'RSA',
        'file_size'   => strlen($data),
        'duration'    => $duration,
        'memory_used' => $memUsed,
        'type'        => 'ENCRYPT',
    ]);

    // 14) Feedback
    session()->flash('download_file', $outName);
    session()->flash('success', 'RSA encryption successful!');

    return redirect()->back();
}

    public function encryptHybrid(Request $request)
{
    // 1) Validation
    $request->validate([
        'file'         => 'required|file',
        'filename'     => 'required|string',
        'password'     => 'required|string|min:4',
        'recipient_id' => 'required|exists:users,id',
    ]);

    // 2) Exclude unsafe types
    $file      = $request->file('file');
    $excluded  = ['jpg','jpeg','png','exe','dll','bat'];
    $ext       = strtolower($file->getClientOriginalExtension());
    $origName  = $file->getClientOriginalName();
    if (in_array($ext, $excluded)) {
        return back()->withErrors(['file' => 'This file type is not allowed for encryption.']);
    }
    if (str_ends_with($origName, '.enc')) {
        return back()->withErrors(['file' => 'This file is already encrypted.']);
    }

    // 3) Prepare names & paths
    $password    = $request->input('password');
    $recipientId = $request->input('recipient_id');
    $outName     = $request->input('filename') . '.enc';
    $inPath      = $file->getRealPath();
    $encDir      = storage_path('app/encrypted');
    if (!file_exists($encDir)) {
        mkdir($encDir, 0777, true);
    }
    $outPath     = "$encDir/$outName";

    // 4) Start profiling
    $startTime = microtime(true);
    $startMem  = memory_get_usage();

    // 5) Generate AES key + IV
    $aesKey = random_bytes(32);
    $iv     = random_bytes(16);

    // 6) Encrypt AES key with recipient’s public RSA key
    $recipient = \App\Models\User::findOrFail($recipientId);
    $pubKeyPEM = $recipient->public_key;
    if (! $pubKeyPEM) {
        return back()->withErrors(['recipient_id' => 'Recipient public key not found.']);
    }
    if (! openssl_public_encrypt(
        $aesKey,
        $encryptedAESKey,
        $pubKeyPEM,
        OPENSSL_PKCS1_OAEP_PADDING
    )) {
        return back()->withErrors(['file' => 'Failed to encrypt AES key with public key.']);
    }

    // 7) Build header: HYB + 2-byte key length + encrypted AES key + IV
    $hdr  = 'HYB';
    $hdr .= pack('n', strlen($encryptedAESKey));
    $hdr .= $encryptedAESKey;
    $hdr .= $iv;

    // 8) Open streams and write header
    $in  = fopen($inPath, 'rb');
    $out = fopen($outPath, 'wb');
    fwrite($out, $hdr);

    // 9) Stream-encrypt the file in 1 MB chunks
    $chunkSize = 1024 * 1024;
    while (! feof($in)) {
        $plain  = fread($in, $chunkSize);
        $cipher = openssl_encrypt(
            $plain,
            'aes-256-cbc',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        fwrite($out, $cipher);
        // carry last 16 bytes as next IV (CBC chaining)
        $iv = substr($cipher, -16);
    }
    fclose($in);

    // 10) Append SHA-256(password) hash for later verification
    $hashPayload = hash('sha256', $password);
    fwrite($out, $hashPayload);
    fclose($out);

    // 11) Stop profiling
    $duration = round(microtime(true) - $startTime, 5);
    $memUsed  = memory_get_usage() - $startMem;

    // 12) Log it
    \App\Models\EncryptionLog::create([
        'user_id'     => Auth::id(),
        'file_name'   => $outName,
        'algorithm'   => 'HYBRID',
        'file_size'   => $file->getSize(),
        'duration'    => $duration,
        'memory_used' => $memUsed,
        'type'        => 'ENCRYPT',
        'recipient_id'=> $recipient->id,
    ]);

    // 13) Flash and return
    session()->flash('download_file', $outName);
    session()->flash('success', 'Hybrid encryption successful!');
    return redirect()->back();
}


    public function decryptAES(Request $request)
{
    $request->validate([
        'file'     => 'required|file',
        'password' => 'required|string|min:4',
    ]);

    // 1) Start profiling
    $startTime = microtime(true);
    $startMem  = memory_get_usage();

    // 2) Paths and streams
    $uploaded = $request->file('file')->getRealPath();
    $outDir   = storage_path('app/decrypted');
    if (! file_exists($outDir)) {
        mkdir($outDir, 0777, true);
    }
    $outName  = 'decrypted_aes_' . time() . '.bin';
    $outPath  = "$outDir/$outName";

    $in  = fopen($uploaded, 'rb');
    $out = fopen($outPath, 'wb');

    // 3) Read & check header
    $signature = fread($in, 3);
    if ($signature !== 'AES') {
        fclose($in); fclose($out);
        return back()->withErrors(['file' => 'Invalid file format.']);
    }

    // 4) Pull salt, IV
    $salt = fread($in, 16);
    $iv   = fread($in, 16);

    // 5) Derive key & init HMAC
    $password = $request->input('password');
    $key      = hash_pbkdf2('sha256', $password, $salt, 100000, 32, true);
    $hmacCtx  = hash_init('sha256', HASH_HMAC, $key);
    hash_update($hmacCtx, $salt . $iv);

    // 6) Determine how many bytes are cipher (total − header − HMAC)
    $stats     = fstat($in);
    $totalSize = $stats['size'];
    $headerLen = 3 + 16 + 16;
    $tagLen    = 32;
    $cipherLen = $totalSize - $headerLen - $tagLen;

    // 7) Stream-decrypt in chunks
    $chunkSize = 1024 * 1024; // 1 MB
    $bytesRead = 0;
    while ($bytesRead < $cipherLen && ! feof($in)) {
        $toRead = min($chunkSize, $cipherLen - $bytesRead);
        $cipher = fread($in, $toRead);
        hash_update($hmacCtx, $cipher);

        $plain = openssl_decrypt(
            $cipher,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );

        if ($plain === false) {
            fclose($in); fclose($out);
            return back()->withErrors(['file' => 'Decryption error (corrupt chunk).']);
        }

        fwrite($out, $plain);
        $bytesRead += $toRead;

        // CBC chain: last block becomes next IV
        $iv = substr($cipher, -16);
    }

    // 8) Read & verify HMAC tag
    $tagStored  = fread($in, $tagLen);
    $tagCalcBin = hash_final($hmacCtx, true);

    fclose($in);
    if (! hash_equals($tagStored, $tagCalcBin)) {
        fclose($out);
        unlink($outPath);
        return back()->withErrors(['password' => 'Wrong password or tampered file.']);
    }

    fclose($out);

    // 9) Stop profiling & log
    $duration = round(microtime(true) - $startTime, 5);
    $memUsed  = memory_get_usage() - $startMem;
    \App\Models\EncryptionLog::create([
        'user_id'     => auth()->id(),
        'file_name'   => $request->file('file')->getClientOriginalName(),
        'algorithm'   => 'AES',
        'file_size'   => $request->file('file')->getSize(),
        'duration'    => $duration,
        'memory_used' => $memUsed,
        'type'        => 'DECRYPT',
    ]);

    // 10) Return with download link
    session()->flash('success', 'AES decryption successful!');
    session()->flash('download_url', route('download.decrypted', ['filename' => $outName]));
    session()->flash('download_name', $outName);

    return redirect()->route('decrypt.form');
}


    public function decryptRSA(Request $request)
{
    // 1) Validate inputs
    $request->validate([
        'file'        => 'required|file',
        'private_key' => 'required|file',
        'password'    => 'required|string|min:4',
    ]);

    // 2) Start profiling
    $startTime = microtime(true);
    $startMem  = memory_get_usage();

    // 3) Load uploaded files
    $encFile        = $request->file('file');
    $keyFile        = $request->file('private_key');
    $password       = $request->input('password');
    $encData        = file_get_contents($encFile->getRealPath());
    $privatePemData = file_get_contents($keyFile->getRealPath());

    // 4) Check format
    if (substr($encData, 0, 3) !== 'RSA') {
        return back()->withErrors(['file' => 'Invalid file format.']);
    }

    // 5) Extract cipher + hash
    $payload    = substr($encData, 3);
    $cipher     = substr($payload, 0, -64);
    $storedHash = substr($payload, -64);
    $inputHash  = hash('sha256', $password);

    // 6) Verify password hash
    if (! hash_equals($storedHash, $inputHash)) {
        return back()->withErrors(['password' => 'Incorrect password.']);
    }

    // 7) Unlock private key
    $privateKey = openssl_pkey_get_private($privatePemData, $password);
    if (! $privateKey) {
        return back()->withErrors(['private_key' => 'Failed to load private key with that password.']);
    }

    // 8) Decrypt
    if (! openssl_private_decrypt($cipher, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
        $error = openssl_error_string();
        return back()->withErrors(['file' => "RSA decryption failed. $error"]);
    }

    // 9) Write output
    $outputName    = 'decrypted_rsa_' . time() . '.bin';
    $decryptedDir  = storage_path('app/decrypted');
    if (! file_exists($decryptedDir)) {
        mkdir($decryptedDir, 0777, true);
    }
    file_put_contents("$decryptedDir/$outputName", $decrypted);

    // 10) Stop profiling
    $duration = round(microtime(true) - $startTime, 5);
    $memUsed  = memory_get_usage() - $startMem;

    // 11) Log
    \App\Models\EncryptionLog::create([
        'user_id'     => auth()->id(),
        'file_name'   => $encFile->getClientOriginalName(),
        'algorithm'   => 'RSA',
        'file_size'   => $encFile->getSize(),
        'duration'    => $duration,
        'memory_used' => $memUsed,
        'type'        => 'DECRYPT',
    ]);

    // 12) Flash success & download link
    session()->flash('success', 'RSA decryption successful!');
    session()->flash(
        'download_url',
        route('download.decrypted', ['filename' => $outputName])
    );
    session()->flash('download_name', $outputName);

    return redirect()->route('decrypt.form');
}

    public function decryptHybrid(Request $request)
{
    // 1) Validate inputs
    $request->validate([
        'file'        => 'required|file',
        'private_key' => 'required|file',
        'password'    => 'required|string|min:4',
    ]);

    // 2) Start profiling
    $startTime = microtime(true);
    $startMem  = memory_get_usage();

    // 3) Prepare paths
    $encFile  = $request->file('file');
    $keyFile  = $request->file('private_key');
    $password = $request->input('password');

    $inPath   = $encFile->getRealPath();
    $outDir   = storage_path('app/decrypted');
    if (! file_exists($outDir)) {
        mkdir($outDir, 0777, true);
    }
    $outName  = 'decrypted_hybrid_' . time() . '.bin';
    $outPath  = "$outDir/$outName";

    // 4) Open streams
    $in  = fopen($inPath, 'rb');
    $out = fopen($outPath, 'wb');

    // 5) Read & verify header
    $sig = fread($in, 3);
    if ($sig !== 'HYB') {
        fclose($in); fclose($out);
        return back()->withErrors(['file' => 'Invalid file format.']);
    }

    // 6) Read encrypted AES key length & data
    $lenData = fread($in, 2);
    $keyLen  = unpack('n', $lenData)[1];
    $encryptedAESKey = fread($in, $keyLen);

    // 7) Read IV
    $iv = fread($in, 16);

    // 8) Determine file sizes
    $stats     = fstat($in);
    $totalSize = $stats['size'];
    $headerLen = 3 + 2 + $keyLen + 16;
    $tagLen    = 64; // SHA-256 hex string length

    // 9) Verify embedded password hash
    fseek($in, -$tagLen, SEEK_END);
    $storedHash = fread($in, $tagLen);
    $inputHash  = hash('sha256', $password);

    if (! hash_equals($storedHash, $inputHash)) {
        fclose($in); fclose($out);
        return back()->withErrors(['password' => 'Incorrect password.']);
    }

    // 10) Decrypt AES key with the user’s private RSA key
    $privatePem = file_get_contents($keyFile->getRealPath());
    $privateKey = openssl_pkey_get_private($privatePem, $password);
    if (! $privateKey) {
        fclose($in); fclose($out);
        return back()->withErrors(['private_key' => 'Failed to load private key.']);
    }
    if (! openssl_private_decrypt(
        $encryptedAESKey,
        $aesKey,
        $privateKey,
        OPENSSL_PKCS1_OAEP_PADDING
    )) {
        fclose($in); fclose($out);
        return back()->withErrors(['file' => 'Failed to decrypt AES key.']);
    }

    // 11) Stream-decrypt the AES payload in 1 MB chunks
    fseek($in, $headerLen);
    $chunkSize = 1024 * 1024;
    while (ftell($in) < $totalSize - $tagLen && ! feof($in)) {
        $toRead    = min($chunkSize, $totalSize - $tagLen - ftell($in));
        $cipherChunk = fread($in, $toRead);
        $plainChunk  = openssl_decrypt(
            $cipherChunk,
            'aes-256-cbc',
            $aesKey,
            OPENSSL_RAW_DATA,
            $iv
        );
        if ($plainChunk === false) {
            fclose($in); fclose($out);
            return back()->withErrors(['file' => 'Decryption failed.']);
        }
        fwrite($out, $plainChunk);
        $iv = substr($cipherChunk, -16);
    }

    // 12) Close streams
    fclose($in);
    fclose($out);

    // 13) Stop profiling & log
    $duration = round(microtime(true) - $startTime, 5);
    $memUsed  = memory_get_usage() - $startMem;

    \App\Models\EncryptionLog::create([
        'user_id'     => auth()->id(),
        'file_name'   => $encFile->getClientOriginalName(),
        'algorithm'   => 'HYBRID',
        'file_size'   => $encFile->getSize(),
        'duration'    => $duration,
        'memory_used' => $memUsed,
        'type'        => 'DECRYPT',
    ]);

    // 14) Return with download link
    session()->flash('success', 'Hybrid decryption successful!');
    session()->flash(
        'download_url',
        route('download.decrypted', ['filename' => $outName])
    );
    session()->flash('download_name', $outName);

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
