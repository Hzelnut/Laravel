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
        ]);

        $file = $request->file('file');
        $password = $request->input('password');
        $filename = $file->getClientOriginalName();
        $data = file_get_contents($file->getRealPath());

        $start = microtime(true); // start time

        // Encrypt using AES-256-CBC + HMAC
        $salt = random_bytes(16);
        $key = hash_pbkdf2("sha256", $password, $salt, 100000, 32, true);
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($data, 'aes-256-cbc', $key, OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $salt . $iv . $cipher, $key, true);
        $encrypted = 'AES' . $salt . $iv . $cipher . $hmac;

        // Save encrypted file
        $outputName = pathinfo($filename, PATHINFO_FILENAME) . '.enc';
        $path = storage_path("app/encrypted");
                if (!file_exists($path)) {
            mkdir($path, 0777, true);
        }
        file_put_contents("$path/$outputName", $encrypted);
        $end = microtime(true); // end time

        // Log to DB
        EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'AES',
            'file_size' => strlen($data),
            'duration' => round($end - $start, 3),
        ]);
        session()->flash('success', 'AES encryption successful!');
        return response()->download(storage_path("app/encrypted/$outputName"))->deleteFileAfterSend();
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

        Storage::put("decrypted/$outputName", $decrypted);
        session()->flash('success', 'File decrypted successfully!');
        return response()->download(storage_path("app/decrypted/$outputName"))->deleteFileAfterSend();
    }
    public function showRSAEncryptForm()
    {
        return view('rsa_encrypt');
    }

    public function encryptRSA(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'password' => 'required|string|min:4',
        ]);

        $file = $request->file('file');
        $password = $request->input('password');
        $filename = $file->getClientOriginalName();
        $data = file_get_contents($file->getRealPath());

        $start = microtime(true);

        $privateKeyConfig = [
            "digest_alg" => "sha256",
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];
        $res = openssl_pkey_new($privateKeyConfig);
        openssl_pkey_export($res, $privateKeyPEM, $password);
        $publicKeyDetails = openssl_pkey_get_details($res);
        $publicKeyPEM = $publicKeyDetails["key"];

        if (strlen($data) > 190) {
            return back()->withErrors(['file' => 'RSA can only encrypt small files. Use Hybrid mode for larger files.']);
        }

        openssl_public_encrypt($data, $encryptedData, $publicKeyPEM, OPENSSL_PKCS1_OAEP_PADDING);
        $output = 'RSA' . $encryptedData;

        $outputName = pathinfo($filename, PATHINFO_FILENAME) . '_rsa.enc';
        Storage::put("encrypted/$outputName", $output);

        $keyFile = pathinfo($filename, PATHINFO_FILENAME) . '_private.pem';
        Storage::put("keys/$keyFile", $privateKeyPEM);

        $end = microtime(true);

        EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'RSA',
            'file_size' => strlen($data),
            'duration' => round($end - $start, 3),
        ]);

        return response()->download(storage_path("app/encrypted/$outputName"))->deleteFileAfterSend();
    }

    public function showRSADecryptForm()
    {
        return view('rsa_decrypt');
    }

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

        // Load private key with password
        $privateKey = openssl_pkey_get_private($privateKeyData, $password);
        if (!$privateKey) {
            return back()->withErrors(['private_key' => 'Invalid private key or wrong password.']);
        }

        // Decrypt
        if (!openssl_private_decrypt($cipher, $decrypted, $privateKey, OPENSSL_PKCS1_OAEP_PADDING)) {
            return back()->withErrors(['file' => 'Decryption failed.']);
        }

        $outputName = 'decrypted_rsa_' . time() . '.txt';
        Storage::put("decrypted/$outputName", $decrypted);

        return response()->download(storage_path("app/decrypted/$outputName"))->deleteFileAfterSend();
    }

    public function showHybridEncryptForm()
    {
        return view('hybrid_encrypt');
    }

    public function encryptHybrid(Request $request)
    {
        $request->validate([
            'file' => 'required|file',
            'password' => 'required|string|min:4',
        ]);

        $file = $request->file('file');
        $password = $request->input('password');
        $filename = $file->getClientOriginalName();
        $data = file_get_contents($file->getRealPath());

        $start = microtime(true);

        $aesKey = random_bytes(32);
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($data, 'aes-256-cbc', $aesKey, OPENSSL_RAW_DATA, $iv);

        $keyConfig = [
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA,
        ];
        $rsa = openssl_pkey_new($keyConfig);
        openssl_pkey_export($rsa, $privateKeyPEM, $password);
        $pubKeyDetails = openssl_pkey_get_details($rsa);
        $publicKeyPEM = $pubKeyDetails["key"];

        openssl_public_encrypt($aesKey, $encryptedAESKey, $publicKeyPEM, OPENSSL_PKCS1_OAEP_PADDING);

        $hybridData = 'HYB' . pack('n', strlen($encryptedAESKey)) . $encryptedAESKey . $iv . $cipher;

        $outputName = pathinfo($filename, PATHINFO_FILENAME) . '_hybrid.enc';
        Storage::put("encrypted/$outputName", $hybridData);

        $keyName = pathinfo($filename, PATHINFO_FILENAME) . '_private.pem';
        Storage::put("keys/$keyName", $privateKeyPEM);

        $end = microtime(true);

        EncryptionLog::create([
            'user_id' => Auth::id(),
            'file_name' => $filename,
            'algorithm' => 'HYBRID',
            'file_size' => strlen($data),
            'duration' => round($end - $start, 3),
        ]);

        return response()->download(storage_path("app/encrypted/$outputName"))->deleteFileAfterSend();
    }

    public function showHybridDecryptForm()
    {
        return view('hybrid_decrypt');
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

        Storage::put("decrypted/$outputName", $decrypted);
        return response()->download(storage_path("app/decrypted/$outputName"))->deleteFileAfterSend();
    }

    public function showHistory()
    {
        $logs = EncryptionLog::where('user_id', Auth::id())->latest()->get();
        return view('history', compact('logs'));
    }


}
