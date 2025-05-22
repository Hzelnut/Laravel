<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\FileController;
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

    // Unified Encryption Form
    Route::get('/encrypt', [FileController::class, 'showEncryptForm'])->name('encrypt.form');
    Route::post('/encrypt/auto', [FileController::class, 'autoEncrypt'])->name('encrypt.auto');

    // Individual encryption methods
    Route::post('/encrypt/aes', [FileController::class, 'encryptAES'])->name('encrypt.aes');
    Route::post('/encrypt/rsa', [FileController::class, 'encryptRSA'])->name('encrypt.rsa');
    Route::post('/encrypt/hybrid', [FileController::class, 'encryptHybrid'])->name('encrypt.hybrid');

    // Decryption routes
    Route::get('/decrypt', [FileController::class, 'showDecryptForm'])->name('decrypt.form');
    Route::post('/decrypt/aes', [FileController::class, 'decryptAES'])->name('decrypt.aes');

    Route::get('/decrypt/rsa', [FileController::class, 'showRSADecryptForm'])->name('decrypt.rsa.form');
    Route::post('/decrypt/rsa', [FileController::class, 'decryptRSA'])->name('decrypt.rsa');

    Route::get('/decrypt/hybrid', [FileController::class, 'showHybridDecryptForm'])->name('decrypt.hybrid.form');
    Route::post('/decrypt/hybrid', [FileController::class, 'decryptHybrid'])->name('decrypt.hybrid');

    // History
    Route::get('/history', [FileController::class, 'showHistory'])->name('history');

    // Encrypted file download
    Route::get('/download/encrypted/{filename}', function ($filename) {
    $path = storage_path("app/encrypted/{$filename}");

    if (!file_exists($path)) {
        abort(404);
    }

    // Custom name for download (keep .enc extension)
    $downloadName = session('original_name')
        ? pathinfo(session('original_name'), PATHINFO_FILENAME) . '.' . pathinfo($filename, PATHINFO_EXTENSION)
        : $filename;

    return response()->download($path, $downloadName)->deleteFileAfterSend();
})->name('download.encrypted')->middleware('auth');



});

require __DIR__.'/auth.php';
