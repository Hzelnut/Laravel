<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class EncryptionLog extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'recipient_id', // include this if you're logging recipients
        'file_name',
        'algorithm',
        'file_size',
        'duration',
        'type', // include this if you're distinguishing ENCRYPT/DECRYPT
    ];

    /**
     * Get the user who performed the operation (encrypt/decrypt).
     */
    public function user()
    {
        return $this->belongsTo(User::class, 'user_id');
    }

    /**
     * Get the recipient user (for encryption logs with recipients).
     */
    public function recipient()
    {
        return $this->belongsTo(User::class, 'recipient_id');
    }
}
