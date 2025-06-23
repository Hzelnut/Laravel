<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Add 'memory_used' column to 'encryption_logs' table.
     */
    public function up(): void
    {
        Schema::table('encryption_logs', function (Blueprint $table) {
            $table->bigInteger('memory_used')->nullable();
        });
    }

    /**
     * Remove 'memory_used' column from 'encryption_logs' table.
     */
    public function down(): void
    {
        Schema::table('encryption_logs', function (Blueprint $table) {
            $table->dropColumn('memory_used');
        });
    }
};
