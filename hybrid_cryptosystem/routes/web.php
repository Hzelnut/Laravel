<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\FileController;
use App\Http\Controllers\KeyController;
use Illuminate\Support\Facades\Auth;

// Public Route
Route::get('/', function () {
    return view('welcome');
});

// Dashboard
Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');

// Authenticated Routes
Route::middleware('auth')->group(function () {

    // 🔐 Profile
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    // 🔏 Encryption
    Route::get('/encrypt', [FileController::class, 'showEncryptForm'])->name('encrypt.form');
    Route::post('/encrypt/auto', [FileController::class, 'autoEncrypt'])->name('encrypt.auto');
    Route::post('/encrypt/aes', [FileController::class, 'encryptAES'])->name('encrypt.aes');
    Route::post('/encrypt/rsa', [FileController::class, 'encryptRSA'])->name('encrypt.rsa');
    Route::post('/encrypt/hybrid', [FileController::class, 'encryptHybrid'])->name('encrypt.hybrid');

    // 🔓 Decryption
    Route::get('/decrypt', fn() => view('decrypt_all'))->name('decrypt.form');
    Route::post('/decrypt/auto', [FileController::class, 'autoDecrypt'])->name('decrypt.auto');

    // 📊 Encryption History
    Route::get('/history', [FileController::class, 'showHistory'])->name('history');
    Route::get('/history/received', [FileController::class, 'receivedHistory'])->name('history.received');

    // Reset history
    Route::post('/history/reset', function () {
        \App\Models\EncryptionLog::where('user_id', Auth::id())->delete();
        return redirect()->route('history')->with('success', 'History cleared.');
    })->name('history.reset');

    // 🔐 Private Key Download
    Route::get('/key/download', [KeyController::class, 'download'])->name('key.download');

    // 📥 Download Decrypted Files
    Route::get('/download/decrypted/{filename}', function ($filename) {
        $path = storage_path("app/decrypted/" . basename($filename));
        abort_unless(file_exists($path), 404);
        return response()->download($path)->deleteFileAfterSend();
    })->name('download.decrypted');

    // 📤 Download Encrypted Files
    Route::get('/download/encrypted/{filename}', function ($filename) {
        $filename = basename($filename);
        $path = storage_path("app/encrypted/{$filename}");

        abort_unless(file_exists($path), 404);

        $downloadName = session('original_name')
            ? pathinfo(session('original_name'), PATHINFO_FILENAME) . '.' . pathinfo($filename, PATHINFO_EXTENSION)
            : $filename;

        return response()->download($path, $downloadName)->deleteFileAfterSend();
    })->name('download.encrypted');
});

require __DIR__ . '/auth.php';
