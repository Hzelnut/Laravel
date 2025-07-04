<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\FileController;
use App\Http\Controllers\KeyController;
use Illuminate\Support\Facades\Response;

Route::get('/', function () {
    return view('welcome');
});

Route::get('/dashboard', function () {
    return view('dashboard');
})->middleware(['auth', 'verified'])->name('dashboard');

// Routes that require authentication
Route::middleware('auth')->group(function () {

    // Profile routes
    Route::get('/profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('/profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::delete('/profile', [ProfileController::class, 'destroy'])->name('profile.destroy');

    // Unified encryption page (Blade: encrypt_all.blade.php)
    Route::get('/encrypt', [FileController::class, 'showEncryptForm'])->name('encrypt.form');
    Route::post('/encrypt/auto', [FileController::class, 'autoEncrypt'])->name('encrypt.auto');

    // Optional: if using separate encryption methods
    Route::post('/encrypt/aes', [FileController::class, 'encryptAES'])->name('encrypt.aes');
    Route::post('/encrypt/rsa', [FileController::class, 'encryptRSA'])->name('encrypt.rsa');
    Route::post('/encrypt/hybrid', [FileController::class, 'encryptHybrid'])->name('encrypt.hybrid');

    // Decryption
    Route::get('/decrypt', function () {
        return view('decrypt_all');
    })->name('decrypt.form');
    Route::post('/decrypt/auto', [FileController::class, 'autoDecrypt'])->name('decrypt.auto');

    // Encryption history
    Route::get('/history', [FileController::class, 'showHistory'])->name('history');

    // Private key download
    Route::get('/download-private-key', [KeyController::class, 'download'])->name('download.private.key');

    // Secure decrypted file download
    Route::get('/download/decrypted/{filename}', function ($filename) {
        $filename = basename($filename);
        $path = storage_path("app/decrypted/{$filename}");

        if (!file_exists($path)) {
            abort(404);
        }

        return response()->download($path)->deleteFileAfterSend();
    })->name('download.decrypted');

    // Secure encrypted file download
    Route::get('/download/encrypted/{filename}', function ($filename) {
        $filename = basename($filename);
        $path = storage_path("app/encrypted/{$filename}");

        if (!file_exists($path)) {
            abort(404);
        }

        $downloadName = session('original_name')
            ? pathinfo(session('original_name'), PATHINFO_FILENAME) . '.' . pathinfo($filename, PATHINFO_EXTENSION)
            : $filename;

        return response()->download($path, $downloadName)->deleteFileAfterSend();
    })->name('download.encrypted');
});

require __DIR__.'/auth.php';
