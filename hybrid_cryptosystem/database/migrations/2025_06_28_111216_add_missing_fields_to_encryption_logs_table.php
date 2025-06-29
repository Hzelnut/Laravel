<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
{
    Schema::table('encryption_logs', function (Blueprint $table) {
        if (!Schema::hasColumn('encryption_logs', 'recipient_id')) {
            $table->foreignId('recipient_id')->nullable()->constrained('users')->onDelete('set null');
        }
        if (!Schema::hasColumn('encryption_logs', 'type')) {
            $table->string('type')->default('ENCRYPT');
        }
        if (!Schema::hasColumn('encryption_logs', 'memory_used')) {
            $table->bigInteger('memory_used')->nullable();
        }
    });
}


public function down(): void
{
    Schema::table('encryption_logs', function (Blueprint $table) {
        $table->dropForeign(['recipient_id']);
        $table->dropColumn(['recipient_id', 'type', 'memory_used']);
    });
}

};
