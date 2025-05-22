<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Storage;
use Illuminate\Support\Facades\Auth;
use App\Models\EncryptionLog;

class FileController extends Controller
{
    public function showEncryptForm()
    {
        return view('encrypt');
    }

    public function encryptAES(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'password' => 'required|string|min:4',
            'filename' => 'required|string'
        ]);

        $file = $request->file('file');
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

    public function showDecryptForm()
    {
        return view('decrypt');
    }

    public function decryptAES(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'password' => 'required|string|min:4',
        ]);

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
        $outputName = 'decrypted_' . time() . '.txt';

        $decryptedPath = storage_path('app/decrypted');
        if (!file_exists($decryptedPath)) {
            mkdir($decryptedPath, 0777, true);
        }

        Storage::put("decrypted/$outputName", $decrypted);

        session()->flash('success', 'File decrypted successfully!');
        return response()->download(storage_path("app/decrypted/$outputName"))->deleteFileAfterSend();
    }

    public function encryptRSA(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'filename' => 'nullable|string',
            'password' => 'nullable|string|min:4',
        ]);

        $file = $request->file('file');
        $filename = $request->input('filename') ?: $file->getClientOriginalName();
        $password = $request->input('password');
        $data = file_get_contents($file->getRealPath());

        if (strlen($data) > 190) {
            return back()->withErrors(['file' => 'RSA can only encrypt small files. Use Hybrid for large files.']);
        }

        $start = microtime(true);

        $keyConfig = [
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($keyConfig);
        if (!$res) {
            $msg = "Failed to generate RSA key. OpenSSL error: " . implode(", ", array_filter([openssl_error_string()]));
            return back()->withErrors(['file' => $msg]);
        }

        openssl_pkey_export($res, $privateKeyPEM, $password ?: null);
        $pubKeyDetails = openssl_pkey_get_details($res);
        $publicKeyPEM = $pubKeyDetails["key"];

        openssl_public_encrypt($data, $encryptedData, $publicKeyPEM, OPENSSL_PKCS1_OAEP_PADDING);
        $output = 'RSA' . $encryptedData;

        $encFilename = pathinfo($filename, PATHINFO_FILENAME) . '_rsa.enc';
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
        session()->flash('original_name', $encFilename); // renamed for download
        session()->flash('success', 'RSA encryption successful!');
        return redirect()->back();
    }

    public function encryptHybrid(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'filename' => 'required|string',
            'password' => 'required|string|min:4',
        ]);

        $file = $request->file('file');
        $filename = $request->input('filename') . '.enc';
        $password = $request->input('password');
        $data = file_get_contents($file->getRealPath());

        $start = microtime(true);

        $aesKey = random_bytes(32);
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($data, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);

        $rsaConfig = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];

        $res = openssl_pkey_new($rsaConfig);
        if (!$res) {
            $msg = "Failed to generate RSA key. OpenSSL error: " . implode(", ", array_filter([openssl_error_string()]));
            return back()->withErrors(['file' => $msg]);
        }

        openssl_pkey_export($res, $privateKeyPEM, $password);
        $pubKeyDetails = openssl_pkey_get_details($res);
        $publicKeyPEM = $pubKeyDetails["key"];

        openssl_public_encrypt($aesKey, $encryptedAESKey, $publicKeyPEM, OPENSSL_PKCS1_OAEP_PADDING);
        $hybridData = 'HYB' . pack('n', strlen($encryptedAESKey)) . $encryptedAESKey . $iv . $cipher;

        $encPath = storage_path("app/encrypted");
        $keyPath = storage_path("app/keys");

        if (!file_exists($encPath)) mkdir($encPath, 0777, true);
        if (!file_exists($keyPath)) mkdir($keyPath, 0777, true);

        file_put_contents("$encPath/$filename", $hybridData);
        file_put_contents("$keyPath/" . pathinfo($filename, PATHINFO_FILENAME) . '_private.pem', $privateKeyPEM);

        $end = microtime(true);

        EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'HYBRID',
            'file_size' => strlen($data),
            'duration' => round($end - $start, 3),
        ]);

        session()->flash('success', 'Hybrid encryption successful! Download will begin now.');
        session()->flash('download_file', $filename);
        session()->flash('original_name', $filename);

        return redirect()->back();
    }

    public function showRSAEncryptForm() { return view('rsa_encrypt'); }
    public function showRSADecryptForm() { return view('rsa_decrypt'); }
    public function showHybridEncryptForm() { return view('hybrid_encrypt'); }
    public function showHybridDecryptForm() { return view('hybrid_decrypt'); }

    public function decryptRSA(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'private_key' => 'required|file',
            'password' => 'required|string|min:4',
        ]);

        $encFile = $request->file('file');
        $keyFile = $request->file('private_key');
        $password = $request->input('password');

        $encData = file_get_contents($encFile->getRealPath());
        $privateKeyData = file_get_contents($keyFile->getRealPath());

        if (substr($encData, 0, 3) !== 'RSA') {
            return back()->withErrors(['file' => 'Invalid file format.']);
        }

        $cipher = substr($encData, 3);

        $privateKey = openssl_pkey_get_private($privateKeyData, $password);
        if (!$privateKey) {
            return back()->withErrors(['private_key' => 'Invalid private key or wrong password.']);
        }

        if (!openssl_private_decrypt($cipher, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return back()->withErrors(['file' => 'Decryption failed.']);
        }

        $outputName = 'decrypted_rsa_' . time() . '.txt';

        $decryptedPath = storage_path('app/decrypted');
        if (!file_exists($decryptedPath)) {
            mkdir($decryptedPath, 0777, true);
        }

        Storage::put("decrypted/$outputName", $decrypted);
        session()->flash('success', 'RSA decryption successful!');
        return response()->download(storage_path("app/decrypted/$outputName"))->deleteFileAfterSend();
    }

    public function decryptHybrid(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'private_key' => 'required|file',
            'password' => 'required|string|min:4',
        ]);

        $encFile = $request->file('file');
        $keyFile = $request->file('private_key');
        $password = $request->input('password');

        $encData = file_get_contents($encFile->getRealPath());
        $privateKeyData = file_get_contents($keyFile->getRealPath());

        if (substr($encData, 0, 3) !== 'HYB') {
            return back()->withErrors(['file' => 'Invalid file format.']);
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
        $outputName = 'decrypted_hybrid_' . time() . '.txt';

        $decryptedPath = storage_path('app/decrypted');
        if (!file_exists($decryptedPath)) {
            mkdir($decryptedPath, 0777, true);
        }

        Storage::put("decrypted/$outputName", $decrypted);
        session()->flash('success', 'Hybrid decryption successful!');
        return response()->download(storage_path("app/decrypted/$outputName"))->deleteFileAfterSend();
    }

    public function showHistory()
    {
        $logs = EncryptionLog::where('user_id', Auth::id())->latest()->get();
        return view('history', compact('logs'));
    }

        public function autoEncrypt(Request $request)
    {
        $method = $request->input('method');

        if ($method === 'AES') {
            return $this->encryptAES($request);
        } elseif ($method === 'RSA') {
            return $this->encryptRSA($request);
        } elseif ($method === 'HYBRID') {
            return $this->encryptHybrid($request);
        }

        return back()->withErrors(['method' => 'Invalid encryption method selected.']);
    }
}
