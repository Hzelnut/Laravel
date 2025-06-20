<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up()
{
    Schema::table('users', function (Blueprint $table) {
        $table->longText('public_key')->nullable();
        $table->longText('private_key')->nullable(); // optional encrypted backup
    });
}

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            //
        });
    }
};
