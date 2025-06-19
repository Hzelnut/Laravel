<?php

namespace App\Providers;

use Illuminate\Support\ServiceProvider;
use Illuminate\Support\Facades\Event;
use Illuminate\Auth\Events\Login;

class AppServiceProvider extends ServiceProvider
{
    public function boot()
    {
        Event::listen(Login::class, function ($event) {
            if ($event->user) {
                $event->user->update([
                    'last_login_at' => now(),
                ]);
            }
        });
    }
}
