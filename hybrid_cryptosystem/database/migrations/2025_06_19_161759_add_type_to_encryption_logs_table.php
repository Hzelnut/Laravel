<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * This adds a 'type' column to distinguish between encryption and decryption logs.
     */
    public function up()
    {
        Schema::table('encryption_logs', function (Blueprint $table) {
            $table->string('type')
                  ->default('ENCRYPT')
                  ->after('duration');
        });
    }

    /**
     * Reverse the migrations.
     *
     * This drops the 'type' column if rolled back.
     */
    public function down()
    {
        Schema::table('encryption_logs', function (Blueprint $table) {
            $table->dropColumn('type');
        });
    }
};
