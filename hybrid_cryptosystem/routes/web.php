<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\FileController;

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

    // Encryption routes
    Route::get('/encrypt', [FileController::class, 'showEncryptForm'])->name('encrypt.form');
    Route::post('/encrypt/aes', [FileController::class, 'encryptAES'])->name('encrypt.aes');

    // Decryption route (protected by auth)
    Route::get('/decrypt', [FileController::class, 'showDecryptForm'])->name('decrypt.form')->middleware('auth');
    Route::post('/decrypt/aes', [FileController::class, 'decryptAES'])->name('decrypt.aes')->middleware('auth');

    Route::get('/encrypt/rsa', [FileController::class, 'showRSAEncryptForm'])->name('encrypt.rsa.form')->middleware('auth');
    Route::post('/encrypt/rsa', [FileController::class, 'encryptRSA'])->name('encrypt.rsa')->middleware('auth');

    Route::get('/decrypt/rsa', [FileController::class, 'showRSADecryptForm'])->name('decrypt.rsa.form')->middleware('auth');
    Route::post('/decrypt/rsa', [FileController::class, 'decryptRSA'])->name('decrypt.rsa')->middleware('auth');

    Route::get('/encrypt/hybrid', [FileController::class, 'showHybridEncryptForm'])->name('encrypt.hybrid.form');
    Route::post('/encrypt/hybrid', [FileController::class, 'encryptHybrid'])->name('encrypt.hybrid');

    Route::get('/decrypt/hybrid', [FileController::class, 'showHybridDecryptForm'])->name('decrypt.hybrid.form')->middleware('auth');
    Route::post('/decrypt/hybrid', [FileController::class, 'decryptHybrid'])->name('decrypt.hybrid')->middleware('auth');

    Route::get('/history', [FileController::class, 'showHistory'])->name('history')->middleware('auth');


});

require __DIR__.'/auth.php';
