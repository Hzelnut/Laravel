<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Factories\HasFactory;

class EncryptionLog extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'file_name',
        'algorithm',
        'file_size',
        'duration',
    ];

    /**
     * Get the user that owns the log.
     */
    public function user()
    {
        return $this->belongsTo(\App\Models\User::class);
    }
}
